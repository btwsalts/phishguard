from flask import Flask, render_template, request
from analyzer.url_analyzer import analyze_url

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error = "Enter a URL to analyze."
        else:
            try:
                result = analyze_url(url)
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "The URL could not be analyzed."
    return render_template("index.html", result=result, error=error, url=url)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
