# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

if { [file exists $env(LIB_DIR)/perf/qtrace.tcl] == 1} {
    if { [catch {source $env(LIB_DIR)/perf/qtrace.tcl} issue ] } {
        puts "QTrace not available: $issue"
    }

    proc start_qtrace { { qtfile qtrace.qt } } {
        QTrace::Initialize p9 mysim
        QTrace::Start $qtfile mysim
    }

    proc stop_qtrace { } {
        QTrace::Stop mysim
    }
}
