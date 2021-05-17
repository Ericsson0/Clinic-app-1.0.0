from flaskblog import app

if __name__ == "__main__":
    app.jinja_env.cache = {}
    app.run(debug=True)  