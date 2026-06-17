#include "source/extensions/bootstrap/reverse_tunnel/common/rping_interceptor.h"

#include <cstring>

#include "source/common/network/io_socket_error_impl.h"
#include "source/extensions/bootstrap/reverse_tunnel/common/reverse_connection_utility.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

Api::IoCallUint64Result RpingInterceptor::read(Buffer::Instance& buffer,
                                               std::optional<uint64_t> max_length_opt) {
  const uint64_t max_length = max_length_opt.value_or(UINT64_MAX);
  if (max_length == 0) {
    return Api::ioCallUint64ResultNoError();
  }

  // The implementation of IoSocketHandleImpl::read() is copied here and modified to call
  // IoSocketHandleImpl::readv() directly so that our readv() override (which handles the TLS BIO
  // path) is not invoked.
  Buffer::Reservation reservation = buffer.reserveForRead();
  Api::IoCallUint64Result result =
      IoSocketHandleImpl::readv(std::min(reservation.length(), max_length), reservation.slices(),
                                reservation.numSlices());
  const uint64_t bytes_to_commit = result.ok() ? result.return_value_ : 0;
  reservation.commit(bytes_to_commit);

  ENVOY_LOG(trace, "RpingInterceptor: read result: {}", result.return_value_);

  // If RPING keepalives are still active, check whether the incoming data is a RPING message.
  if (ping_echo_active_ && result.err_ == nullptr && result.return_value_ > 0) {
    const uint64_t expected = ReverseConnectionUtility::PING_MESSAGE.size();

    // Compare up to the expected size using a zero-copy view.
    const uint64_t len = std::min<uint64_t>(buffer.length(), expected);
    const char* data = static_cast<const char*>(buffer.linearize(len));
    absl::string_view peek_sv{data, static_cast<size_t>(len)};

    // Check if we have a complete RPING message.
    if (len == expected && ReverseConnectionUtility::isPingMessage(peek_sv)) {
      // Found a complete RPING. Echo and drain it from the buffer.
      buffer.drain(expected);
      onPingMessage();

      // If buffer only contained RPING, return showing we processed it.
      if (buffer.length() == 0) {
        return Api::IoCallUint64Result{expected, Api::IoError::none()};
      }

      // RPING followed by application data. Disable echo and return the remaining data.
      ENVOY_LOG(trace,
                "RpingInterceptor: received application data after RPING, "
                "disabling RPING echo for FD: {}",
                fd_);
      ping_echo_active_ = false;
      // The adjusted return value is the number of bytes excluding the drained RPING. It should be
      // transparent to upper layers that the RPING was processed.
      const uint64_t adjusted =
          (result.return_value_ >= expected) ? (result.return_value_ - expected) : 0;
      return Api::IoCallUint64Result{adjusted, Api::IoError::none()};
    }

    // If partial data could be the start of RPING (only when fewer than expected bytes).
    if (len < expected) {
      const absl::string_view rping_prefix =
          ReverseConnectionUtility::PING_MESSAGE.substr(0, static_cast<size_t>(len));
      if (peek_sv == rping_prefix) {
        ENVOY_LOG(trace,
                  "RpingInterceptor: partial RPING received ({} bytes), waiting "
                  "for more.",
                  len);
        return result; // Wait for more data.
      }
    }

    // Data is not RPING (complete or partial). Disable echo permanently.
    ENVOY_LOG(trace,
              "RpingInterceptor: received application data ({} bytes), "
              "disabling RPING echo for FD: {}",
              len, fd_);
    ping_echo_active_ = false;
  }

  return result;
}

Api::IoCallUint64Result RpingInterceptor::readv(uint64_t max_length, Buffer::RawSlice* slices,
                                                uint64_t num_slice) {
  if (!ping_echo_active_) {
    return IoSocketHandleImpl::readv(max_length, slices, num_slice);
  }

  // This function is called by BoringSSL's BIO layer (source/common/tls/io_handle_bio.cc) with a
  // single slice pointing into a large char[] buffer.  We intercept RPING keepalives here so they
  // are absorbed before reaching the TLS record parser, which would otherwise reject them with
  // WRONG_VERSION_NUMBER.

  const uint64_t expected = ReverseConnectionUtility::PING_MESSAGE.size();
  ASSERT(num_slice >= 1, "readv called with zero slices");
  uint64_t total_new;

  if (!partial_ping_.empty()) {
    // A previous call stashed a partial RPING prefix.  Reserve space at the front of slice[0]
    // so we can prepend the stash after reading without a separate allocation.
    const uint64_t stash_len = partial_ping_.size();
    ASSERT(stash_len < static_cast<uint64_t>(slices[0].len_));
    Buffer::RawSlice adjusted{static_cast<char*>(slices[0].mem_) + stash_len,
                              slices[0].len_ - stash_len};
    const uint64_t adj_max = (max_length > stash_len) ? (max_length - stash_len) : 0;
    Api::IoCallUint64Result result = IoSocketHandleImpl::readv(adj_max, &adjusted, 1);
    if (!result.ok() || result.return_value_ == 0) {
      return result; // Error or EAGAIN; stash is preserved for the next call.
    }
    // Prepend the stash into the reserved space at the front of slice[0].
    std::memcpy(slices[0].mem_, partial_ping_.data(), stash_len);
    total_new = stash_len + result.return_value_;
    partial_ping_.clear();
  } else {
    Api::IoCallUint64Result result = IoSocketHandleImpl::readv(max_length, slices, num_slice);
    ENVOY_LOG(trace, "RpingInterceptor::readv: {} bytes read",
              result.ok() ? result.return_value_ : 0);
    if (!result.ok() || result.return_value_ == 0) {
      return result;
    }
    total_new = result.return_value_;
  }

  // Inspect the leading bytes of slice[0] for a RPING pattern.  The TLS BIO always calls readv
  // with a single large slice, so the entire RPING message will always reside in slice[0].
  const char* data = static_cast<const char*>(slices[0].mem_);
  const uint64_t inspect_len = std::min(total_new, expected);
  absl::string_view peek{data, inspect_len};

  if (inspect_len == expected && ReverseConnectionUtility::isPingMessage(peek)) {
    // Complete RPING: echo it and discard it from the caller's buffer.
    onPingMessage();
    const uint64_t remaining = total_new - expected;
    if (remaining == 0) {
      // Only the RPING was present.  Return EAGAIN so the BIO retries and waits for the real
      // TLS ClientHello — returning 0/none would be misinterpreted as EOF.
      ENVOY_LOG(trace,
                "RpingInterceptor::readv: complete RPING absorbed, returning EAGAIN, FD: {}", fd_);
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }
    // RPING was followed by application data.  Shift the app data to the front of slice[0].
    ENVOY_LOG(trace,
              "RpingInterceptor::readv: RPING + {} app bytes, disabling echo, FD: {}", remaining,
              fd_);
    ping_echo_active_ = false;
    std::memmove(slices[0].mem_, data + expected, remaining);
    return {remaining, Api::IoError::none()};
  }

  if (inspect_len < expected) {
    // Fewer bytes than a full RPING: check whether they could be a RPING prefix.
    const absl::string_view rping_prefix =
        ReverseConnectionUtility::PING_MESSAGE.substr(0, inspect_len);
    if (peek == rping_prefix) {
      // Stash the partial prefix and signal EAGAIN so the BIO retries when more data arrives.
      partial_ping_.assign(data, inspect_len);
      ENVOY_LOG(trace,
                "RpingInterceptor::readv: partial RPING ({} bytes), stashing, FD: {}", inspect_len,
                fd_);
      return {0, Network::IoSocketError::getIoSocketEagainError()};
    }
  }

  // Not a RPING.  Disable echo permanently and pass the data through unmodified.
  ENVOY_LOG(trace, "RpingInterceptor::readv: non-RPING ({} bytes), disabling echo, FD: {}",
            total_new, fd_);
  ping_echo_active_ = false;
  return {total_new, Api::IoError::none()};
}

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
