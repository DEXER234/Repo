import streamlit as st
import pandas as pd
import streamlit_authenticator as stauth
import bcrypt
import os
import requests

# Initialize session state
if 'auth_status' not in st.session_state:
    st.session_state.auth_status = False

# Load user database
def load_users():
    if os.path.exists("users.csv"):
        return pd.read_csv("users.csv")
    return pd.DataFrame(columns=["email", "username", "password"])

# Load news articles
def load_articles():
    if os.path.exists("articles.csv"):
        return pd.read_csv("articles.csv")
    return pd.DataFrame(columns=["title", "content", "author"])

users = load_users()
articles = load_articles()

# Save user to database
def save_user(email, username, password):
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    new_user = pd.DataFrame({"email": [email], "username": [username], "password": [hashed_pw]})
    new_user.to_csv("users.csv", mode='a', index=False, header=False)

# User authentication
def authenticate_user(email, password):
    user = users[users['email'] == email]
    if not user.empty and bcrypt.checkpw(password.encode(), user.iloc[0]['password'].encode()):
        return user.iloc[0]['username']
    return None

# Fetch real news articles from an API
def fetch_news():
    api_key = "08c6016dd4c84ab29d292a2efab337cc"  # Replace with your actual API key
    url = f"https://newsapi.org/v2/top-headlines?country=us&apiKey={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json().get('articles', [])
    return []

# Update display_articles to show fetched news
def display_articles():
    st.title("📰 News Articles")
    articles = fetch_news()  # Fetch real news articles
    for article in articles:
        with st.expander(article['title']):
            st.write(f"**Author**: {article.get('author', 'Unknown')}")
            st.write(article['description'])
            if 'urlToImage' in article:
                st.image(article['urlToImage'], use_column_width=True)
            st.markdown(f"**Read more**: [🔗 {article['url']}]({article['url']})")

# Streamlit Authenticator setup
def login():
    st.title("🔒 Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        username = authenticate_user(email, password)
        if username:
            st.session_state.auth_status = True
            st.session_state.username = username
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid email or password")

def signup():
    st.title("📝 Signup")
    email = st.text_input("Email")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Signup"):
        if password != confirm_password:
            st.error("Passwords do not match!")
        elif users[users['email'] == email].empty:
            save_user(email, username, password)
            st.success("Account created! Please login.")
        else:
            st.error("Email already exists!")

# Main app flow
def main():
    st.sidebar.title("Navigation")
    options = ["Home", "Signup", "Login", "Logout"] if not st.session_state.auth_status else ["Home", "Logout"]
    choice = st.sidebar.selectbox("Choose an option", options)

    if choice == "Home":
        if st.session_state.auth_status:
            st.sidebar.success(f"Logged in as {st.session_state.username}")
            display_articles()
        else:
            st.info("Please login to view articles.")
    elif choice == "Signup":
        signup()
    elif choice == "Login":
        login()
    elif choice == "Logout":
        st.session_state.auth_status = False
        st.session_state.username = None
        st.success("Logged out successfully!")

if __name__ == "__main__":
    main()
