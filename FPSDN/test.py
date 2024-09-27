import networkx as nx
import matplotlib.pyplot as plt


times = [56, 0.0001, 24]

n = len(times)
bar_width = 0.05
x = [0.1, 0.3, 0.5]

plt.bar([p for p in x], times, width=bar_width, label="Total Extraction Time", color='g', align="center")

plt.xlabel("")
plt.ylabel("Time (Seconds)")
xticks_label = ["Preprocessing Time", "DyNetKAT Extraction Time","DyNetKAT Time"]
plt.xticks([p for p in x],xticks_label)
plt.yscale('log')

for i in range(len(x)):
    if i == 1:
        plt.text(x[i], times[i] + 0.0001, str(times[i]), ha='center',  color = 'black', fontweight = 'bold')
    else:
        plt.text(x[i], times[i] + 0.1, str(times[i]), ha='center',  color = 'black', fontweight = 'bold')
        
path = "./FPSDN/output/result3.png"
plt.savefig(path, format="PNG")
plt.close()