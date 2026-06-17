#pragma once

#include <string>

#include "source/common/network/io_socket_handle_impl.h"

namespace Envoy {
namespace Extensions {
namespace Bootstrap {
namespace ReverseConnection {

class RpingInterceptor : public virtual Network::IoSocketHandleImpl {
public:
  // Intercept Buffer-based reads (non-TLS path) to handle reverse-connection keep-alive pings.
  Api::IoCallUint64Result read(Buffer::Instance& buffer,
                               std::optional<uint64_t> max_length) override;

  // Intercept slice-based reads (TLS BIO path) to handle reverse-connection keep-alive pings.
  // BoringSSL's BIO reads through readv(), bypassing read(), so both must be overridden.
  Api::IoCallUint64Result readv(uint64_t max_length, Buffer::RawSlice* slices,
                                uint64_t num_slice) override;

  virtual void onPingMessage() PURE;

protected:
  // Whether to actively echo RPING messages while the connection is idle.
  // Disabled permanently after the first non-RPING application byte is observed.
  bool ping_echo_active_{true};

  // Partial RPING prefix stash for readv() calls: holds bytes that arrived fragmented
  // across multiple readv() calls and look like the start of a RPING message.
  std::string partial_ping_;
};

} // namespace ReverseConnection
} // namespace Bootstrap
} // namespace Extensions
} // namespace Envoy
