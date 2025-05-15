# SPDX-License-Identifier: Apache-2.0

set(OPENOCD_NRF5_INTERFACE "stlink")
set(BOARD_DEBUG_RUNNER openocd)

if(NOT DEFINED OPENOCD_NRF5_SUBFAMILY)
  string(REGEX MATCH nrf5. OPENOCD_NRF5_SUBFAMILY "${BOARD}")

  if(HWMv2 AND "${OPENOCD_NRF5_SUBFAMILY}" STREQUAL "")
    string(REGEX MATCH nrf5. OPENOCD_NRF5_SUBFAMILY "${BOARD_QUALIFIERS}")
  endif()
endif()

set(pre_init_cmds
  "set WORKAREASIZE 0x4000"	# 16 kB RAM used for flashing
  "source [find interface/${OPENOCD_NRF5_INTERFACE}.cfg]"
  "source [find target/${OPENOCD_NRF5_SUBFAMILY}.cfg]"
)

foreach(cmd ${pre_init_cmds})
  board_runner_args(openocd --cmd-pre-init "${cmd}")
endforeach()

include(${ZEPHYR_BASE}/boards/common/openocd.board.cmake)