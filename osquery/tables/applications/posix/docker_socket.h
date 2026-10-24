/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

namespace osquery {
namespace tables {

/**
 * @brief Resolve the docker socket path to connect to.
 *
 * Docker Desktop and Podman on macOS do not create /var/run/docker.sock;
 * the API socket lives under the user home directory instead. When the
 * docker_socket flag is left at its default value and /var/run/docker.sock
 * does not exist, this falls back to ~/.docker/run/docker.sock when that
 * file is present, so the docker_ tables work without extra configuration.
 * An explicitly configured flag always wins.
 */
std::string dockerSocketEndpoint();

} // namespace tables
} // namespace osquery
