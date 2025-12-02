from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug True for local dev; set False for production
    app.run(host="0.0.0.0", port=5001, debug=True)
