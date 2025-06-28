# xiatoumailreg

A web service for Mastodon users to register for an email account on the Mailu server.

## Setup

1.  Clone the repository.
2.  Create a Mastodon App: Go to your Mastodon instance's settings, create a new application, and get the Client ID and Client Secret.
3.  Create a `.env` file based on the provided requirements.
4.  Install dependencies: `pip install -r requirements.txt`
5.  Run the application: `uvicorn main:app --reload`

## API Endpoints

-   `/`: Landing page
-   `/login`: Redirects to Mastodon for OAuth
-   `/callback`: Handles the OAuth callback
-   `/register`: Handles new user registration
-   `/logout`: Clears the user session
