"""
visualizer.py
Builds Plotly figures for the Streamlit dashboard: attack timelines,
top attacker/target bar charts, success/failure pie charts, hourly
heatmaps, daily trends, and severity distribution.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import constants
from analyzer import Statistics
from detector import Alert
from logger import get_logger
from parser import LogEntry

logger = get_logger(__name__)

_TEMPLATE = "plotly_dark"


def _empty_figure(message: str = "No data available") -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message, xref="paper", yref="paper", x=0.5, y=0.5,
        showarrow=False, font=dict(size=16, color="gray"),
    )
    fig.update_layout(template=_TEMPLATE, height=350)
    return fig


def attack_timeline(alerts: List[Alert]) -> go.Figure:
    """Scatter timeline of alerts colored by severity."""
    if not alerts:
        return _empty_figure("No alerts to display")

    df = pd.DataFrame([{
        "timestamp": a.timestamp,
        "severity": a.severity,
        "alert_type": a.alert_type,
        "ip": a.ip,
        "username": a.username,
        "failed_attempts": a.failed_attempts,
    } for a in alerts if a.timestamp is not None])

    if df.empty:
        return _empty_figure("No timestamped alerts to display")

    fig = px.scatter(
        df, x="timestamp", y="alert_type", color="severity",
        size="failed_attempts", hover_data=["ip", "username", "failed_attempts"],
        color_discrete_map=constants.SEVERITY_COLORS,
        title="Attack Timeline",
    )
    fig.update_layout(template=_TEMPLATE, height=400, xaxis_title="Time", yaxis_title="Alert Type")
    return fig


def top_attacker_ips_chart(stats: Statistics) -> go.Figure:
    if not stats.top_attacker_ips:
        return _empty_figure("No attacker data available")

    df = pd.DataFrame(stats.top_attacker_ips, columns=["ip", "failed_attempts"])
    fig = px.bar(
        df, x="failed_attempts", y="ip", orientation="h",
        title="Top Attacker IPs", color="failed_attempts",
        color_continuous_scale="Reds",
    )
    fig.update_layout(template=_TEMPLATE, height=400, yaxis={"categoryorder": "total ascending"})
    return fig


def top_targeted_users_chart(stats: Statistics) -> go.Figure:
    if not stats.top_targeted_users:
        return _empty_figure("No targeted-user data available")

    df = pd.DataFrame(stats.top_targeted_users, columns=["username", "failed_attempts"])
    fig = px.bar(
        df, x="failed_attempts", y="username", orientation="h",
        title="Top Targeted Usernames", color="failed_attempts",
        color_continuous_scale="Oranges",
    )
    fig.update_layout(template=_TEMPLATE, height=400, yaxis={"categoryorder": "total ascending"})
    return fig


def success_vs_failure_pie(stats: Statistics) -> go.Figure:
    labels = ["Successful", "Failed", "Invalid User"]
    values = [stats.successful_logins, stats.failed_logins, stats.invalid_user_attempts]
    if sum(values) == 0:
        return _empty_figure("No login events available")

    fig = px.pie(
        names=labels, values=values, title="Login Outcome Distribution",
        color=labels,
        color_discrete_map={
            "Successful": "#22c55e", "Failed": "#ef4444", "Invalid User": "#f59e0b",
        },
    )
    fig.update_layout(template=_TEMPLATE, height=380)
    return fig


def hourly_heatmap(entries: List[LogEntry]) -> go.Figure:
    """Heatmap of failed-login volume by day-of-week vs hour-of-day."""
    relevant = [
        e for e in entries
        if e.timestamp is not None
        and e.status in (constants.STATUS_FAILED, constants.STATUS_INVALID_USER)
    ]
    if not relevant:
        return _empty_figure("No failed-login timestamps available")

    day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    grid = defaultdict(int)
    for e in relevant:
        grid[(e.timestamp.weekday(), e.timestamp.hour)] += 1

    z = [[grid.get((d, h), 0) for h in range(24)] for d in range(7)]

    fig = go.Figure(data=go.Heatmap(
        z=z, x=list(range(24)), y=day_names, colorscale="YlOrRd",
    ))
    fig.update_layout(
        template=_TEMPLATE, height=380, title="Failed Login Heatmap (Hour x Day)",
        xaxis_title="Hour of Day", yaxis_title="Day of Week",
    )
    return fig


def daily_attacks_chart(entries: List[LogEntry]) -> go.Figure:
    relevant = [
        e for e in entries
        if e.timestamp is not None
        and e.status in (constants.STATUS_FAILED, constants.STATUS_INVALID_USER)
    ]
    if not relevant:
        return _empty_figure("No failed-login data available")

    counts = Counter(e.timestamp.date() for e in relevant)
    dates = sorted(counts.keys())
    df = pd.DataFrame({"date": dates, "failed_attempts": [counts[d] for d in dates]})

    fig = px.line(
        df, x="date", y="failed_attempts", markers=True,
        title="Daily Failed Login Attempts",
    )
    fig.update_layout(template=_TEMPLATE, height=380)
    return fig


def severity_distribution_chart(stats: Statistics) -> go.Figure:
    breakdown = stats.severity_breakdown
    if not breakdown or sum(breakdown.values()) == 0:
        return _empty_figure("No alerts generated")

    labels = list(breakdown.keys())
    values = [breakdown[k] for k in labels]

    fig = px.bar(
        x=labels, y=values, color=labels,
        color_discrete_map=constants.SEVERITY_COLORS,
        title="Alert Severity Distribution",
        labels={"x": "Severity", "y": "Count"},
    )
    fig.update_layout(template=_TEMPLATE, height=380, showlegend=False)
    return fig
