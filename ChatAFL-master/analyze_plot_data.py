import pandas as pd
import matplotlib.pyplot as plt

# Load the plot_data file
file_path = "/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/benchmark/temp_extracted/out-lightftp-chatafl/plot_data"
data = pd.read_csv(file_path, comment='#', header=None)

# Assign column names
data.columns = [
    "unix_time", "cycles_done", "cur_path", "paths_total", "pending_total", "pending_favs",
    "map_size", "unique_crashes", "unique_hangs", "max_depth", "execs_per_sec",
    "n_nodes", "n_edges", "chat_times"
]

# Convert unix_time to a readable format
data['unix_time'] = pd.to_datetime(data['unix_time'], unit='s')

# Plot paths_total over time
plt.figure(figsize=(10, 6))
plt.plot(data['unix_time'], data['paths_total'], label='Paths Total', color='blue')
plt.xlabel('Time')
plt.ylabel('Paths Total')
plt.title('Paths Total Over Time')
plt.legend()
plt.grid()
plt.savefig("paths_total_over_time.png")
plt.show()

# Plot unique_crashes over time
plt.figure(figsize=(10, 6))
plt.plot(data['unix_time'], data['unique_crashes'], label='Unique Crashes', color='red')
plt.xlabel('Time')
plt.ylabel('Unique Crashes')
plt.title('Unique Crashes Over Time')
plt.legend()
plt.grid()
plt.savefig("unique_crashes_over_time.png")
plt.show()

# Print summary statistics
print("Summary Statistics:")
print(data.describe())