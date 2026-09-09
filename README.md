# System_Dasboard

# System Vulnerability & Predictive Risk Dashboard

A Flask + Dash web dashboard for a college security assignment. It shows:

- Currently detected vulnerabilities on a (simulated) system
- A **Low / Medium / High** risk rating for each one (based on CVSS score)
- A **machine learning model's prediction** of how likely each vulnerability
  is to actually be exploited in an attack ("Predictive Attack Analysis")
- Charts: risk distribution, vulnerability types, CVSS vs. predicted attack
  probability
- A built-in **glossary** explaining every technical term used

Currently it runs on **mock data** (`data/mock_vulnerabilities.csv`) that
looks like real scanner output, so you can demo it immediately. See
"Using Real Data Later" below for how to swap in a real scan.

---

## Project Structure

```
security_dashboard/
├── app.py                    # Main Dash app — run this
├── requirements.txt
├── data/
│   ├── generate_data.py      # Creates mock + training datasets
│   ├── mock_vulnerabilities.csv   # What the dashboard displays
│   └── training_data.csv          # Larger synthetic set used to train the model
├── model/
│   ├── train_model.py        # Trains the RandomForest risk-prediction model
│   └── risk_model.pkl        # Saved trained model
└── utils/
    └── risk_utils.py         # Risk colors + glossary text
```

---

## Setup in VS Code

1. **Open the folder** `security_dashboard` in VS Code (`File > Open Folder`).

2. **Create a virtual environment** (recommended). Open the VS Code terminal
   (`` Ctrl+` ``) and run:

   **Windows:**
   ```
   python -m venv venv
   venv\Scripts\activate
   ```

   **macOS / Linux:**
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```

   In VS Code, when prompted, select this `venv` as your Python interpreter
   (bottom-right corner, or `Ctrl+Shift+P` → "Python: Select Interpreter").

3. **Install the required libraries:**

   ```
   pip install -r requirements.txt
   ```

   This installs: `dash`, `dash-bootstrap-components`, `plotly`, `pandas`,
   `numpy`, `scikit-learn`, `joblib`.

4. **(Already done for you, but if you ever need to regenerate them)**
   Generate the datasets and train the model:

   ```
   python data/generate_data.py
   python model/train_model.py
   ```

   `data/mock_vulnerabilities.csv` and `model/risk_model.pkl` are already
   included in this project, so you can skip this step unless you want to
   regenerate them with different random data.

5. **Run the dashboard:**

   ```
   python app.py
   ```

6. Open your browser to **http://127.0.0.1:8050**

---

## How the "Predictive Analysis" Works

The model is a `RandomForestClassifier` (scikit-learn) trained on a synthetic
dataset (`training_data.csv`) built from these features:

| Feature | Meaning |
|---|---|
| `cvss_score` | Standard 0–10 severity score |
| `exploit_available` | Is a working exploit publicly known? |
| `patch_available` | Has a fix been released? |
| `days_since_disclosure` | How long the vulnerability has been public |
| `exposure` | Internal network only, or reachable from the internet |
| `category` | Type of vulnerability (SQL Injection, XSS, RCE, etc.) |

The synthetic training labels combine these factors the way a security
analyst would reason about likelihood of exploitation, then add some
random noise, so the model has real patterns to learn — this makes it
appropriate for demonstrating a working ML pipeline in an assignment,
while being transparent that it is **not** trained on real breach data.

For a stronger report/grade, you can mention this explicitly: the
architecture (feature engineering → train/test split → RandomForest →
saved pipeline → live inference) is exactly what you'd use with real
historical incident data; only the data source would change.

---

## Using Real Data Later

To connect real scan results instead of mock data:

1. Run a scanner (e.g. **Nmap**, **OpenVAS**, **Nessus**, or pull from the
   **NVD/CVE API**) and export results.
2. Write a small parser that converts that output into the same columns
   used in `data/mock_vulnerabilities.csv`:
   `vuln_id, system, cve_id, cvss_score, exploit_available,
   patch_available, days_since_disclosure, exposure, category, risk_level`
3. Save it as `data/mock_vulnerabilities.csv` (or point `app.py`'s
   `DATA_PATH` at your new file).
4. Everything else — risk coloring, charts, ML predictions, glossary —
   works automatically since it reads from that CSV.

For real exploitation-likelihood data, EPSS (Exploit Prediction Scoring
System, https://www.first.org/epss/) is a good public dataset to train
against instead of the synthetic labels used here.

---

## Notes for Your Assignment Write-Up

- **Risk Level** (Low/Medium/High) = a *rule-based* rating from the
  standard CVSS score banding (0–3.9 / 4.0–6.9 / 7.0–10).
- **Predicted Attack Likelihood** = a *machine-learning-based* rating,
  separate from CVSS, meant to simulate "given everything we know about
  this vulnerability, how likely is it to be the target of an attack."
- Keeping these two separate (rule-based severity vs. ML-predicted
  likelihood) is intentional — it mirrors real-world security practice,
  where **severity** and **likelihood of exploitation** are distinct
  concepts that together determine priority.
