"""
SentinelScope - Data Analysis & Visualization
===============================================
Exploratory data analysis on RDP brute force attack data
exported from Azure Sentinel Log Analytics Workspace.

Run: python Data_Analysis.py
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import warnings
warnings.filterwarnings('ignore')

plt.style.use('dark_background')

# ── Load Data ─────────────────────────────────────────────────────────────────
df = pd.read_excel('DTI_Project_new.xlsx')
df['TIMESTAMP'] = pd.to_datetime(df['TIMESTAMP'])
df['HOUR']      = df['TIMESTAMP'].dt.hour
df['MONTH']     = df['TIMESTAMP'].dt.strftime('%Y-%m')
df['DAYOFWEEK'] = df['TIMESTAMP'].dt.day_name()

print(f"Dataset shape: {df.shape}")
print(f"Date range: {df['TIMESTAMP'].min()} → {df['TIMESTAMP'].max()}")
print(f"Countries: {df['COUNTRY'].nunique()}")
print(f"Unique usernames: {df['USERNAME'].nunique()}")
print(f"\nTop 5 attacking countries:\n{df['COUNTRY'].value_counts().head()}")

# ── 1. Attack Frequency by Label ──────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 4))
df['LABEL'].value_counts().plot(kind='bar', color=['#ff4757', '#2ed573'], ax=ax)
ax.set_title('Attack Event Types Detected by Azure Sentinel')
ax.set_ylabel('Frequency')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('plot_event_types.png', dpi=150)
plt.show()

# ── 2. Top Attacking Countries ────────────────────────────────────────────────
top_countries = df['COUNTRY'].value_counts().head(10)
fig = px.treemap(
    names=top_countries.index,
    parents=['' for _ in top_countries.index],
    values=top_countries.values,
    title='Top 10 Countries — RDP Attack Attempts',
    color=top_countries.values,
    color_continuous_scale='Reds'
)
fig.show()

# ── 3. Global Choropleth Map ──────────────────────────────────────────────────
country_counts = df['COUNTRY'].value_counts().reset_index()
country_counts.columns = ['Country', 'Attacks']
fig = px.choropleth(
    country_counts,
    locations='Country', locationmode='country names',
    color='Attacks',
    title='Global Distribution of RDP Brute Force Attacks',
    color_continuous_scale='Reds',
    labels={'Attacks': 'Attack Attempts'}
)
fig.show()

# ── 4. Top Usernames ──────────────────────────────────────────────────────────
top_usernames = df['USERNAME'].value_counts().head(15)
fig, ax = plt.subplots(figsize=(10, 5))
ax.barh(top_usernames.index[::-1], top_usernames.values[::-1], color='#ff6348')
ax.set_title('Top 15 Most Attempted Usernames in Brute Force Attacks')
ax.set_xlabel('Number of Attempts')
ax.grid(True, alpha=0.2, axis='x')
plt.tight_layout()
plt.savefig('plot_usernames.png', dpi=150)
plt.show()

# ── 5. Attack Heatmap (Hour vs Day) ──────────────────────────────────────────
pivot = df.pivot_table(index='DAYOFWEEK', columns='HOUR',
                       values='USERNAME', aggfunc='count', fill_value=0)
day_order = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']
pivot = pivot.reindex(day_order)

fig, ax = plt.subplots(figsize=(16, 5))
sns.heatmap(pivot, cmap='Reds', linewidths=0.3, ax=ax,
            cbar_kws={'label': 'Attack Count'})
ax.set_title('Attack Heatmap: Hour of Day vs Day of Week')
ax.set_xlabel('Hour (UTC)')
plt.tight_layout()
plt.savefig('plot_heatmap.png', dpi=150)
plt.show()

# ── 6. Monthly Trend ──────────────────────────────────────────────────────────
monthly = df.groupby('MONTH').size().reset_index(name='Attacks')
fig = px.line(monthly, x='MONTH', y='Attacks',
              title='Monthly Attack Volume', markers=True)
fig.update_traces(line_color='#ff4757')
fig.show()

print("\nAll plots saved. Done!")
