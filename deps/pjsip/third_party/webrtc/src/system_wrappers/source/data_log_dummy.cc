/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include "data_log.h"

namespace webrtc {

int DataLog::CreateLog() {
  return 0;
}

void DataLog::ReturnLog() {
}

int DataLog::AddTable(const std::string& /*table_name*/) {
  return 0;
}

int DataLog::AddColumn(const std::string& /*table_name*/,
                       const std::string& /*column_name*/,
                       int /*multi_value_length*/) {
  return 0;
}

int DataLog::NextRow(const std::string& /*table_name*/) {
  return 0;
}

DataLogImpl::DataLogImpl() {
}

DataLogImpl::~DataLogImpl() {
}

DataLogImpl* DataLogImpl::StaticInstance() {
  return NULL;
}

void DataLogImpl::ReturnLog() {
}

int DataLogImpl::AddTable(const std::string& /*table_name*/) {
  return 0;
}

int DataLogImpl::AddColumn(const std::string& /*table_name*/,
                           const std::string& /*column_name*/,
                           int /*multi_value_length*/) {
  return 0;
}

int DataLogImpl::InsertCell(const std::string& /*table_name*/,
                            const std::string& /*column_name*/,
                            const Container* /*value_container*/) {
  return 0;
}

int DataLogImpl::NextRow(const std::string& /*table_name*/) {
  return 0;
}

void DataLogImpl::Flush() {
}

bool DataLogImpl::Run(void* /*obj*/) {
  return true;
}

void DataLogImpl::Process() {
}

void DataLogImpl::StopThread() {
}

}  // namespace webrtc
