perf record --call-graph=fp -e 'sched:sched_switch' -e 'sched:sched_stat_sleep' -e 'sched:sched_stat_blocked' --pid $(pgrep a.out | head -n 1) -- sleep 1
perf script -f time,comm,pid,tid,event,ip,sym,dso,trace -i sched.data | ~/FlameGraph/stackcollapse-perf-sched.awk | ~/FlameGraph/flamegraph.pl --color=io --countname=us &gt;off-cpu.svg
