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
      for data_type in ['nodes', 'edges']:
        #get subject & fuzzer & cov_type-specific dataframe
        df1 = df[(df['subject'] == subject) & 
                         (df['fuzzer'] == fuzzer) & 
                         (df['state_type'] == data_type)]

        mean_list.append((subject, fuzzer, data_type, 0, 0.0))
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
          mean_list.append((subject, fuzzer, data_type, time, cov_total / max(run_count,1)))

  #Convert the list to a dataframe
  mean_df = pd.DataFrame(mean_list, columns = ['subject', 'fuzzer', 'data_type', 'time', 'data'])
  
  # save to file
  print("Saving mean logs into file...")
  mean_df.to_csv("mean_plot_data.csv", index=False)

  # Explicit color palette: blue, orange, red (replaces default green for better contrast)
  COLOR_PALETTE = ['#1f77b4', '#ff7f0e', '#d62728', '#9467bd', '#8c564b',
                   '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
  # Line styles and markers for visual distinction when lines overlap
  LINE_STYLES = ['-', '--', '-.',   ':', '-', '--', '-.', ':']
  MARKERS     = ['o', 's',  '^',   'D', 'v', 'P',  'X',  '*']
  fuzzer_colors = {f.lower(): COLOR_PALETTE[i % len(COLOR_PALETTE)] for i, f in enumerate(fuzzers)}
  fuzzer_styles = {f.lower(): LINE_STYLES[i % len(LINE_STYLES)] for i, f in enumerate(fuzzers)}
  fuzzer_markers = {f.lower(): MARKERS[i % len(MARKERS)] for i, f in enumerate(fuzzers)}
  marker_every = max(1, cut_off // (step * 10))

  fig, axes = plt.subplots(1, 2, figsize = (20, 10))
  fig.suptitle("State coverage analysis")

  for key, grp in mean_df.groupby(['fuzzer', 'data_type']):
    c = fuzzer_colors.get(key[0], None)
    ls = fuzzer_styles.get(key[0], '-')
    mk = fuzzer_markers.get(key[0], None)
    if key[1] == 'nodes':
      axes[0].plot(grp['time'], grp['data'], color=c, linestyle=ls, marker=mk, markevery=marker_every, markersize=5, linewidth=2)
      axes[0].set_xlabel('Time (in min)')
      axes[0].set_ylabel('#nodes')
    if key[1] == 'edges':
      axes[1].plot(grp['time'], grp['data'], color=c, linestyle=ls, marker=mk, markevery=marker_every, markersize=5, linewidth=2)
      axes[1].set_xlabel('Time (in min)')
      axes[1].set_ylabel('#edges')

  # Auto-zoom Y-axis to data range with padding
  for i, ax in enumerate(fig.axes):
    lines = ax.get_lines()
    if lines:
      all_y = [y for line in lines for y in line.get_ydata()]
      ymin, ymax = min(all_y), max(all_y)
      margin = max((ymax - ymin) * 0.15, 1)
      ax.set_ylim([max(0, ymin - margin), ymax + margin])
    ax.legend(fuzzers, loc='upper left')
    ax.grid(True, alpha=0.3)

  #Save to file
  plt.savefig(out_file)

# Parse the input arguments
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('-i','--csv_file',type=str,required=True,help="Full path to plot_data.csv")
    parser.add_argument('-p','--put',type=str,required=True,help="Name of the subject program")
    parser.add_argument('-r','--runs',type=int,required=True,help="Number of runs in the experiment")
    parser.add_argument('-c','--cut_off',type=int,required=True,help="Cut-off time in minutes")
    parser.add_argument('-s','--step',type=int,required=True,help="Time step in minutes")
    parser.add_argument('-o','--out_file',type=str,required=True,help="Output file")
    parser.add_argument('-f','--fuzzers', nargs='+',required=True,help="List of fuzzers")
    args = parser.parse_args()
    main(args.csv_file, args.put, args.runs, args.cut_off, args.step, args.out_file, args.fuzzers)