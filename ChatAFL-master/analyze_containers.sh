#!/bin/bash

# 分析 CHATAFL vs CHATAFL-OPT 实验结果
# 容器: c69703a2bd5d (CHATAFL), c110c31c1ad8 (CHATAFL-OPT)

RESULTS_DIR="/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/benchmark/results-lightftp_Feb-04_13-18-30"

echo "================================================================================"
echo "🔬 CHATAFL vs CHATAFL-OPT 实验指标分析"
echo "================================================================================"
echo "实验时间: 2026-02-04 13:18:30"
echo "容器ID:"
echo "  - CHATAFL:     c69703a2bd5d (loving_bohr)"
echo "  - CHATAFL-OPT: c110c31c1ad8 (elastic_jemison)"
echo ""

cd "$RESULTS_DIR" || exit 1

# 检查文件
echo "📁 结果文件:"
ls -lh *.tar.gz *.csv
echo ""

# 统计数据记录数
echo "================================================================================"
echo "📊 数据统计"
echo "================================================================================"
echo ""
echo "CSV记录数:"
echo "  CHATAFL:     $(grep -c ',chatafl,' results.csv) 条"
echo "  CHATAFL-OPT: $(grep -c ',chatafl_opt,' results.csv) 条"
echo ""

# 分析最终覆盖率
echo "================================================================================"
echo "📈 最终覆盖率对比"
echo "================================================================================"
echo ""

calculate_final_coverage() {
    local fuzzer=$1
    local cov_type=$2
    
    awk -F',' -v f="$fuzzer" -v ct="$cov_type" '
        $3==f && $5==ct {
            run=$4
            time=$1
            cov=$6
            if (time > max_time[run]) {
                max_time[run] = time
                final_cov[run] = cov
            }
        }
        END {
            sum = 0
            count = 0
            for (run in final_cov) {
                sum += final_cov[run]
                count++
            }
            if (count > 0) print sum / count
            else print 0
        }
    ' results.csv
}

printf "%-25s %15s %15s %15s\n" "指标" "CHATAFL" "CHATAFL-OPT" "差异"
echo "-------------------------------------------------------------------------------"

for metric in "l_per:行覆盖率(%)" "l_abs:行覆盖数(绝对)" "b_per:边覆盖率(%)" "b_abs:边覆盖数(绝对)"; do
    cov_type=$(echo $metric | cut -d':' -f1)
    label=$(echo $metric | cut -d':' -f2)
    
    chatafl_val=$(calculate_final_coverage "chatafl" "$cov_type")
    chatafl_opt_val=$(calculate_final_coverage "chatafl_opt" "$cov_type")
    diff=$(echo "$chatafl_opt_val - $chatafl_val" | bc -l)
    
    printf "%-25s %15.2f %15.2f %+15.2f\n" "$label" "$chatafl_val" "$chatafl_opt_val" "$diff"
done

echo ""

# 时间线分析  
echo "================================================================================"
echo "⏱️  覆盖率增长时间线 (行覆盖率%)"
echo "================================================================================"
echo ""

calculate_coverage_at_time() {
    local fuzzer=$1
    local cov_type=$2
    local time_min=$3
    
    awk -F',' -v f="$fuzzer" -v ct="$cov_type" -v tm="$time_min" '
        $3==f && $5==ct {
            run=$4
            time=$1
            cov=$6
            
            if (start_time[run] == 0) start_time[run] = time
            
            target_time = start_time[run] + tm * 60
            if (time <= target_time) {
                cov_at_time[run] = cov
            }
        }
        END {
            sum = 0
            count = 0
            for (run in cov_at_time) {
                sum += cov_at_time[run]
                count++
            }
            if (count > 0) print sum / count
            else print 0
        }
    ' results.csv
}

printf "%10s %15s %15s %15s\n" "时间(分)" "CHATAFL" "CHATAFL-OPT" "差异"
echo "-------------------------------------------------------------------------------"

for time_min in 0 10 20 30 40 50 60; do
    chatafl_val=$(calculate_coverage_at_time "chatafl" "l_per" $time_min)
    chatafl_opt_val=$(calculate_coverage_at_time "chatafl_opt" "l_per" $time_min)
    diff=$(echo "$chatafl_opt_val - $chatafl_val" | bc -l)
    
    printf "%10d %15.2f %15.2f %+15.2f\n" "$time_min" "$chatafl_val" "$chatafl_opt_val" "$diff"
done

echo ""

# 状态空间探索分析
if [ -f "states.csv" ]; then
    echo "================================================================================"
    echo "🔄 状态空间探索分析"
    echo "================================================================================"
    echo ""
    
    calculate_state_at_time() {
        local fuzzer=$1
        local state_type=$2
        local time_min=$3
        
        awk -F',' -v f="$fuzzer" -v st="$state_type" -v tm="$time_min" '
            $3==f && $5==st {
                run=$4
                time=$1
                state=$6
                
                if (start_time[run] == 0) start_time[run] = time
                
                target_time = start_time[run] + tm * 60
                if (time <= target_time) {
                    state_at_time[run] = state
                }
            }
            END {
                sum = 0
                count = 0
                for (run in state_at_time) {
                    sum += state_at_time[run]
                    count++
                }
                if (count > 0) print sum / count
                else print 0
            }
        ' states.csv
    }
    
    for metric in "nodes:状态节点数" "edges:状态转换边数"; do
        state_type=$(echo $metric | cut -d':' -f1)
        label=$(echo $metric | cut -d':' -f2)
        
        echo "$label:"
        printf "%10s %15s %15s %15s\n" "时间(分)" "CHATAFL" "CHATAFL-OPT" "差异"
        echo "-----------------------------------------------------------------------"
        
        for time_min in 0 10 20 30 40 50 60; do
            chatafl_val=$(calculate_state_at_time "chatafl" "$state_type" $time_min)
            chatafl_opt_val=$(calculate_state_at_time "chatafl_opt" "$state_type" $time_min)
            diff=$(echo "$chatafl_opt_val - $chatafl_val" | bc -l)
            
            printf "%10d %15.2f %15.2f %+15.2f\n" "$time_min" "$chatafl_val" "$chatafl_opt_val" "$diff"
        done
        echo ""
    done
    
    # 最终状态对比
    echo "📊 最终状态空间对比:"
    echo "-------------------------------------------------------------------------------"
    
    calculate_final_state() {
        local fuzzer=$1
        local state_type=$2
        
        awk -F',' -v f="$fuzzer" -v st="$state_type" '
            $3==f && $5==st {
                run=$4
                time=$1
                state=$6
                if (time > max_time[run]) {
                    max_time[run] = time
                    final_state[run] = state
                }
            }
            END {
                sum = 0
                count = 0
                for (run in final_state) {
                    sum += final_state[run]
                    count++
                }
                if (count > 0) print sum / count
                else print 0
            }
        ' states.csv
    }
    
    for metric in "nodes:状态节点数" "edges:状态转换边数"; do
        state_type=$(echo $metric | cut -d':' -f1)
        label=$(echo $metric | cut -d':' -f2)
        
        chatafl_val=$(calculate_final_state "chatafl" "$state_type")
        chatafl_opt_val=$(calculate_final_state "chatafl_opt" "$state_type")
        diff=$(echo "$chatafl_opt_val - $chatafl_val" | bc -l)
        
        printf "%-25s %15.2f %15.2f %+15.2f\n" "$label" "$chatafl_val" "$chatafl_opt_val" "$diff"
    done
    echo ""
fi

# 检查原始数据质量
echo "================================================================================"
echo "🔍 原始数据质量检查"
echo "================================================================================"
echo ""

for fuzzer_file in "chatafl" "chatafl_opt"; do
    for run in 1; do
        tarfile="out-lightftp-${fuzzer_file}_${run}.tar.gz"
        if [ -f "$tarfile" ]; then
            echo "$tarfile:"
            echo "  文件大小: $(du -h $tarfile | cut -f1)"
            
            # 检查cov_over_time.csv行数
            cov_lines=$(tar -xzOf "$tarfile" "out-lightftp-${fuzzer_file}/cov_over_time.csv" 2>/dev/null | wc -l)
            echo "  cov_over_time.csv: $cov_lines 行"
            
            # 检查plot_data行数
            plot_lines=$(tar -xzOf "$tarfile" "out-lightftp-${fuzzer_file}/plot_data" 2>/dev/null | wc -l)
            echo "  plot_data: $plot_lines 行"
            
            # 显示初始和最终覆盖率
            echo "  初始覆盖率:"
            tar -xzOf "$tarfile" "out-lightftp-${fuzzer_file}/cov_over_time.csv" 2>/dev/null | head -2 | tail -1
            echo "  最终覆盖率:"
            tar -xzOf "$tarfile" "out-lightftp-${fuzzer_file}/cov_over_time.csv" 2>/dev/null | tail -1
            echo ""
        fi
    done
done

echo "================================================================================"
echo "✅ 分析完成！"
echo "================================================================================"
