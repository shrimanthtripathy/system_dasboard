"""
app.py
------
System Vulnerability & Predictive Risk Dashboard

A Flask + Dash web app that:
  1. Displays currently detected vulnerabilities with a Low/Medium/High
     risk rating (based on CVSS score).
  2. Uses a trained ML model to predict the likelihood that each
     vulnerability could actually be exploited in an attack.
  3. Explains every technical term used, in plain language.

Run:
    python app.py
Then open:
    http://127.0.0.1:8050
"""

import os
import pandas as pd
import joblib

import plotly.express as px

from dash import Dash, dcc, html, dash_table, Input, Output
import dash_bootstrap_components as dbc

from utils.risk_utils import RISK_COLORS, RISK_BADGE_CLASS, GLOSSARY

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "data", "mock_vulnerabilities.csv")
MODEL_PATH = os.path.join(HERE, "model", "risk_model.pkl")


# model

if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(
        "Mock data not found. Run `python data/generate_data.py` first."
    )
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        "Model not found. Run `python model/train_model.py` first."
    )

df = pd.read_csv(DATA_PATH)
model = joblib.load(MODEL_PATH)

FEATURES = ["cvss_score", "exploit_available", "patch_available",
            "days_since_disclosure", "exposure", "category"]

pred_probs = model.predict_proba(df[FEATURES])
pred_labels = model.predict(df[FEATURES])
class_order = list(model.classes_)
high_idx = class_order.index("High")

df["attack_likelihood"] = pred_labels
df["attack_probability"] = pred_probs[:, high_idx].round(3)

RISK_ORDER = ["Low", "Medium", "High"]


app = Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY, dbc.icons.FONT_AWESOME],
    title="Vulnerability Risk Dashboard",
)
server = app.server  # exposes Flask server (needed for deployment)


def summary_card(title, value, color, icon):
    return dbc.Card(
        dbc.CardBody(
            [
                html.I(className=f"fa-solid {icon} fa-2x mb-2", style={"color": color}),
                html.H3(f"{value}", className="mb-0"),
                html.P(title, className="text-muted mb-0"),
            ]
        ),
        className="text-center shadow-sm h-100",
    )


def make_summary_row(data):
    total = len(data)
    counts = data["risk_level"].value_counts()
    avg_cvss = round(data["cvss_score"].mean(), 1) if total else 0
    return dbc.Row(
        [
            dbc.Col(summary_card("Total Vulnerabilities", total, "#3498db", "fa-shield-halved"), md=3, className="mb-3"),
            dbc.Col(summary_card("High Risk", counts.get("High", 0), RISK_COLORS["High"], "fa-triangle-exclamation"), md=3, className="mb-3"),
            dbc.Col(summary_card("Medium Risk", counts.get("Medium", 0), RISK_COLORS["Medium"], "fa-circle-exclamation"), md=3, className="mb-3"),
            dbc.Col(summary_card("Low Risk", counts.get("Low", 0), RISK_COLORS["Low"], "fa-circle-check"), md=3, className="mb-3"),
        ]
    )


def make_table(data):
    display_cols = [
        "vuln_id", "system", "cve_id", "category", "cvss_score",
        "risk_level", "exposure", "exploit_available", "patch_available",
        "attack_likelihood", "attack_probability",
    ]
    nice_names = {
        "vuln_id": "ID", "system": "System", "cve_id": "CVE",
        "category": "Vulnerability Type", "cvss_score": "CVSS",
        "risk_level": "Risk Level", "exposure": "Exposure",
        "exploit_available": "Exploit Known?", "patch_available": "Patch Available?",
        "attack_likelihood": "Predicted Attack Likelihood",
        "attack_probability": "Attack Probability",
    }
    d = data[display_cols].copy()
    d["exploit_available"] = d["exploit_available"].map({1: "Yes", 0: "No"})
    d["patch_available"] = d["patch_available"].map({1: "Yes", 0: "No"})
    d = d.rename(columns=nice_names)

    style_conditional = []
    for level, color in RISK_COLORS.items():
        style_conditional.append({
            "if": {"filter_query": f'{{Risk Level}} = "{level}"', "column_id": "Risk Level"},
            "backgroundColor": color, "color": "black", "fontWeight": "bold",
        })
        style_conditional.append({
            "if": {"filter_query": f'{{Predicted Attack Likelihood}} = "{level}"', "column_id": "Predicted Attack Likelihood"},
            "backgroundColor": color, "color": "black", "fontWeight": "bold",
        })

    return dash_table.DataTable(
        id="vuln-table",
        columns=[{"name": c, "id": c} for c in d.columns],
        data=d.to_dict("records"),
        sort_action="native",
        filter_action="native",
        page_size=10,
        style_table={"overflowX": "auto"},
        style_cell={
            "backgroundColor": "#1e1e2f", "color": "white",
            "textAlign": "left", "padding": "8px", "fontSize": "13px",
        },
        style_header={"backgroundColor": "#12121c", "fontWeight": "bold", "color": "white"},
        style_data_conditional=style_conditional,
    )


def glossary_accordion():
    items = [
        dbc.AccordionItem(html.P(desc, className="mb-0"), title=term)
        for term, desc in GLOSSARY
    ]
    return dbc.Accordion(items, start_collapsed=True, always_open=False)


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
app.layout = dbc.Container(
    fluid=True,
    children=[
        dbc.Row(dbc.Col(html.Div([
            html.H2([html.I(className="fa-solid fa-shield-halved me-2"), "System Vulnerability & Predictive Risk Dashboard"]),
            html.P("Live view of detected vulnerabilities, their risk level, and an ML-based prediction of attack likelihood.",
                   className="text-muted"),
        ]), width=12), className="mt-3 mb-2"),

        html.Div(id="summary-row"),

        dbc.Row([
            dbc.Col([
                html.Label("Filter by Risk Level"),
                dcc.Dropdown(
                    id="risk-filter",
                    options=[{"label": r, "value": r} for r in RISK_ORDER],
                    value=RISK_ORDER, multi=True, className="text-dark",
                ),
            ], md=4),
            dbc.Col([
                html.Label("Filter by System"),
                dcc.Dropdown(
                    id="system-filter",
                    options=[{"label": s, "value": s} for s in sorted(df["system"].unique())],
                    value=sorted(df["system"].unique()), multi=True, className="text-dark",
                ),
            ], md=8),
        ], className="mb-4"),

        dbc.Row([
            dbc.Col(dcc.Graph(id="risk-pie"), md=4),
            dbc.Col(dcc.Graph(id="category-bar"), md=4),
            dbc.Col(dcc.Graph(id="cvss-vs-prob-scatter"), md=4),
        ], className="mb-4"),

        dbc.Row(dbc.Col([
            html.H4([html.I(className="fa-solid fa-table me-2"), "Detected Vulnerabilities"]),
            html.Div(id="table-container"),
        ]), className="mb-4"),

        dbc.Row(dbc.Col([
            html.H4([html.I(className="fa-solid fa-crosshairs me-2"), "Predictive Attack Analysis"]),
            html.P("The vulnerabilities the model considers MOST likely to be exploited, ranked by predicted attack probability.",
                   className="text-muted"),
            html.Div(id="top-predictions"),
        ]), className="mb-4"),

        dbc.Row(dbc.Col([
            html.H4([html.I(className="fa-solid fa-book me-2"), "Understanding This Dashboard"]),
            html.P("Click any term below for a plain-language explanation.", className="text-muted"),
            glossary_accordion(),
        ]), className="mb-5"),
    ],
)


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------
@app.callback(
    Output("summary-row", "children"),
    Output("table-container", "children"),
    Output("risk-pie", "figure"),
    Output("category-bar", "figure"),
    Output("cvss-vs-prob-scatter", "figure"),
    Output("top-predictions", "children"),
    Input("risk-filter", "value"),
    Input("system-filter", "value"),
)
def update_dashboard(risk_levels, systems):
    risk_levels = risk_levels or []
    systems = systems or []
    filtered = df[df["risk_level"].isin(risk_levels) & df["system"].isin(systems)]

    summary = make_summary_row(filtered)
    table = make_table(filtered) if len(filtered) else html.P("No vulnerabilities match the current filters.")

    if len(filtered):
        pie_fig = px.pie(
            filtered, names="risk_level", title="Risk Level Distribution",
            color="risk_level", color_discrete_map=RISK_COLORS, hole=0.4,
        )
    else:
        pie_fig = px.pie(title="Risk Level Distribution (no data)")
    pie_fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)")

    if len(filtered):
        cat_counts = filtered["category"].value_counts().reset_index()
        cat_counts.columns = ["category", "count"]
        bar_fig = px.bar(
            cat_counts, x="count", y="category", orientation="h",
            title="Vulnerabilities by Type",
        )
        bar_fig.update_layout(yaxis={"categoryorder": "total ascending"})
    else:
        bar_fig = px.bar(title="Vulnerabilities by Type (no data)")
    bar_fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)")

    if len(filtered):
        scatter_fig = px.scatter(
            filtered, x="cvss_score", y="attack_probability",
            color="risk_level", color_discrete_map=RISK_COLORS,
            hover_data=["vuln_id", "system", "category"],
            title="CVSS Score vs Predicted Attack Probability",
            labels={"cvss_score": "CVSS Score", "attack_probability": "Predicted Attack Probability"},
        )
    else:
        scatter_fig = px.scatter(title="CVSS vs Attack Probability (no data)")
    scatter_fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)")

    if len(filtered):
        top = filtered.sort_values("attack_probability", ascending=False).head(5)
        cards = []
        for _, row in top.iterrows():
            badge_color = RISK_BADGE_CLASS.get(row["attack_likelihood"], "secondary")
            cards.append(
                dbc.Card(dbc.CardBody([
                    html.Div([
                        html.H6(f"{row['vuln_id']} — {row['category']}", className="mb-1"),
                        dbc.Badge(row["attack_likelihood"], color=badge_color, className="ms-2"),
                    ], className="d-flex justify-content-between align-items-center"),
                    html.P(f"System: {row['system']}  |  CVE: {row['cve_id']}  |  CVSS: {row['cvss_score']}",
                           className="text-muted mb-1", style={"fontSize": "13px"}),
                    html.P(f"Predicted attack probability: {row['attack_probability']*100:.1f}%",
                           className="mb-0 fw-bold"),
                ]), className="mb-2 shadow-sm")
            )
        top_predictions = cards
    else:
        top_predictions = html.P("No data.")

    return summary, table, pie_fig, bar_fig, scatter_fig, top_predictions


if __name__ == "__main__":
    app.run(debug=True, port=8050)
