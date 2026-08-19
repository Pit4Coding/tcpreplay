#pragma once

#include "packet_edit.h"
#include <string>

bool isRewriteOption(const std::string& option);
bool applyRewriteOption(const std::string& option, const std::string& value, RewriteOptions& rewrite, std::string& error);
