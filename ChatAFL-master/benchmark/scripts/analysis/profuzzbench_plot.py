#!/usr/bin/env python3

import argparse
from pandas import read_csv
from pandas import DataFrame
from pandas import Grouper
from matplotlib import pyplot as plt
import pandas as pd


def main(csv_file, put, runs, cut_off, step, out_file, fuzzers):
  #Read the results
  df = read_csv(csv_file)

  #Calculate the mean of code coverage
  #Store in a list first for efficiency
  mean_list = []

  for subject in [put]:
    for fuzzer in fuzzers:
      fuzzer = fuzzer.lower()
      for cov_type in ['b_abs', 'b_per', 'l_abs', 'l_per']:
        #get subject & fuzzer & cov_type-specific dataframe
        df1 = df[(df['subject'] == subject) & 
                         (df['fuzzer'] == fuzzer) & 
                         (df['cov_type'] == cov_type)]

        if df1.empty:
          continue
        mean_list.append((subject, fuzzer, cov_type, 0, 0.0))
        for time in range(1, cut_off + 1, step):
          cov_total = 0
          run_count = 0

          for run in range(1, runs + 1, 1):
            #get run-specific data frame
            df2 = df1[df1['run'] == run]

            try:
              #get the starting time for this run
              start = df2.iloc[0, 0]

              #get all rows given a cutoff time
              df3 = df2[df2['time'] <= start + time*60]
              
              #update total coverage and #runs
              cov_total += df3.tail(1).iloc[0, 5]
              run_count += 1
            except Exception:
              print("Issue with run {}. Skipping".format(run))
          
          #add a new row
          mean_list.append((subject, fuzzer, cov_type, time, cov_total / max(run_count,1)))

  #Convert the list to a dataframe
  mean_df = pd.DataFrame(mean_list, columns = ['subject', 'fuzzer', 'cov_type', 'time', 'cov'])

  # Explicit color palette: blue, orange, red (replaces default green for better contrast)
  COLOR_PALETTE = ['#1f77b4', '#ff7f0e', '#d62728', '#9467bd', '#8c564b',
                   '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
  # Line styles and markers for visual distinction when lines overlap
  LINE_STYLES = ['-', '--', '-.'  , ':', '-', '--', '-.', ':']
  MARKERS     = ['o', 's',  '^',   'D', 'v', 'P',  'X',  '*']
  fuzzer_colors = {f.lower(): COLOR_PALETTE[i % len(COLOR_PALETTE)] for i, f in enumerate(fuzzers)}
  fuzzer_styles = {f.lower(): LINE_STYLES[i % len(LINE_STYLES)] for i, f in enumerate(fuzzers)}
  fuzzer_markers = {f.lower(): MARKERS[i % len(MARKERS)] for i, f in enumerate(fuzzers)}
  # Marker interval: show a marker every N data points to avoid clutter
  marker_every = max(1, cut_off // (step * 10))

  fig, axes = plt.subplots(2, 2, figsize = (20, 10))
  fig.suptitle("Code coverage analysis")

  for key, grp in mean_df.groupby(['fuzzer', 'cov_type']):
    c = fuzzer_colors.get(key[0], None)
    ls = fuzzer_styles.get(key[0], '-')
    mk = fuzzer_markers.get(key[0], None)
    if key[1] == 'b_abs':
      axes[0, 0].plot(grp['time'], grp['cov'], color=c, linestyle=ls, marker=mk, markevery=marker_every, markersize=5, linewidth=2)
      axes[0, 0].set_xlabel('Time (in min)')
      axes[0, 0].set_ylabel('#edges')
    if key[1] == 'b_per':
      axes[1, 0].plot(grp['time'], grp['cov'], color=c, linestyle=ls, marker=mk, markevery=marker_every, markersize=5, linewidth=2)
      axes[1, 0].set_xlabel('Time (in min)')
      axes[1, 0].set_ylabel('Edge coverage (%)')
    if key[1] == 'l_abs':
      axes[0, 1].plot(grp['time'], grp['cov'], color=c, linestyle=ls, marker=mk, markevery=marker_every, markersize=5, linewidth=2)
      axes[0, 1].set_xlabel('Time (in min)')
      axes[0, 1].set_ylabel('#lines')
    if key[1] == 'l_per':
      axes[1, 1].plot(grp['time'], grp['cov'], color=c, linestyle=ls, marker=mk, markevery=marker_every, markersize=5, linewidth=2)
      axes[1, 1].set_xlabel('Time (in min)')
      axes[1, 1].set_ylabel('Line coverage (%)')

  # Auto-zoom Y-axis to data range (with 5% padding) for abs plots;
  # keep 0-100 for percentage plots
  for i, ax in enumerate(fig.axes):
    lines = ax.get_lines()
    if lines:
      all_y = [y for line in lines for y in line.get_ydata()]
      ymin, ymax = min(all_y), max(all_y)
      # percentage plots (bottom row: index 2,3) keep 0-100
      if i < 2:  # absolute plots (top row)
        margin = max((ymax - ymin) * 0.1, 10)
        ax.set_ylim([max(0, ymin - margin), ymax + margin])
    ax.legend(fuzzers, loc='upper left')
    ax.grid(True, alpha=0.3)

  #Save to file
  plt.savefig(out_file)

# Parse the input arguments
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('-i','--csv_file',type=str,required=True,help="Full path to results.csv")
    parser.add_argument('-p','--put',type=str,required=True,help="Name of the subject program")
    parser.add_argument('-r','--runs',type=int,required=True,help="Number of runs in the experiment")
    parser.add_argument('-c','--cut_off',type=int,required=True,help="Cut-off time in minutes")
    parser.add_argument('-s','--step',type=int,required=True,help="Time step in minutes")
    parser.add_argument('-o','--out_file',type=str,required=True,help="Output file")
    parser.add_argument('-f','--fuzzers', nargs='+',required=True,help="List of fuzzers")
    args = parser.parse_args()
    main(args.csv_file, args.put, args.runs, args.cut_off, args.step, args.out_file,args.fuzzers)
