/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <fstream>

#include <boost/filesystem.hpp>

#include <osquery/core/flags.h>
#include <osquery/tables/applications/posix/docker_socket.h>
#include <osquery/utils/system/env.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

class DockerSocketTests : public testing::Test {
 protected:
  void SetUp() override {
    old_home_ = getEnvVar("HOME");
    temp_dir_ = fs::temp_directory_path() /
                fs::unique_path("osquery_docker_socket_tests-%%%%-%%%%");
    fs::create_directories(temp_dir_ / ".docker" / "run");
    setEnvVar("HOME", temp_dir_.string());
  }

  void TearDown() override {
    if (old_home_) {
      setEnvVar("HOME", *old_home_);
    } else {
      unsetEnvVar("HOME");
    }
    boost::system::error_code ec;
    fs::remove_all(temp_dir_, ec);
  }

  boost::optional<std::string> old_home_;
  fs::path temp_dir_;
};

TEST_F(DockerSocketTests, falls_back_to_user_docker_socket) {
  // No /var/run/docker.sock on the test machine: the default must resolve
  // to the Docker Desktop socket under the fake home directory.
  std::ofstream socket_file(
      (temp_dir_ / ".docker" / "run" / "docker.sock").string());
  socket_file.close();

  EXPECT_EQ(dockerSocketEndpoint(),
            (temp_dir_ / ".docker" / "run" / "docker.sock").string());
}

TEST_F(DockerSocketTests, explicit_flag_wins) {
  std::ofstream socket_file(
      (temp_dir_ / ".docker" / "run" / "docker.sock").string());
  socket_file.close();

  std::string value;
  auto s = Flag::getDefaultValue("docker_socket", value);
  ASSERT_TRUE(s.ok());

  ASSERT_TRUE(
      Flag::updateValue("docker_socket", "/tmp/somewhere/else.sock").ok());
  EXPECT_EQ(dockerSocketEndpoint(), "/tmp/somewhere/else.sock");
  ASSERT_TRUE(Flag::updateValue("docker_socket", value).ok());
}

TEST_F(DockerSocketTests, default_when_no_user_socket) {
  // Neither /var/run/docker.sock nor the user socket exists: keep the
  // default path so the error message mentions the documented location.
  EXPECT_EQ(dockerSocketEndpoint(), Flag::getValue("docker_socket"));
}

} // namespace tables
} // namespace osquery
