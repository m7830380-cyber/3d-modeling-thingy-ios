/* SPDX-FileCopyrightText: 2026 Blender Authors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later */

#pragma once

#include <TargetConditionals.h>

#define MTL_BACKEND_DESKTOP 0
#define MTL_BACKEND_SUPPORTS_RENDER_TARGET_BARRIER 0
#define MTL_BACKEND_SUPPORTS_D24_S8_SYMBOLS 0
#define MTL_BACKEND_SUPPORTS_BORDER_COLOR 0
#define MTL_BACKEND_SUPPORTS_XR 0
#define MTL_BACKEND_REQUIRES_COLOR_ATTACHMENT 1
#define MTL_BACKEND_FORCE_SUBPASS_EMULATION TARGET_OS_SIMULATOR
/* BC pixel format enumerators are marked iOS 16.4+, but the pixel format tables only use them as
 * plain enum values, which need no runtime symbol on older iOS versions. */
#define MTL_BACKEND_PIXEL_FORMAT_TABLES_BEGIN \
  _Pragma("clang diagnostic push") \
      _Pragma("clang diagnostic ignored \"-Wunguarded-availability-new\"")
#define MTL_BACKEND_PIXEL_FORMAT_TABLES_END _Pragma("clang diagnostic pop")
#define GHOST_METAL_CONTEXT_HEADER "intern/GHOST_ContextIOS.hh"
#define GHOST_ContextMetal GHOST_ContextIOS
