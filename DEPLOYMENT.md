# Render Cloud Deployment Guide: CyberShield Portal

Follow these step-by-step instructions to host your containerized NCAS Cyber Portal on Render's free tier.

---

## Step 1: Initialize Git and Push to GitHub

To host on Render, your project files must be stored in a GitHub repository.

1. Open **Command Prompt** or **PowerShell** on your local machine.
2. Navigate to your project directory:
   ```cmd
   cd C:\Users\moham\.gemini\antigravity\scratch\cyber_shield
   ```
3. Initialize git and commit your files:
   ```cmd
   git init
   git add .
   git commit -m "Configure CyberShield Premium Red & White Portal"
   ```
4. Create a new **Public** or **Private** repository on [GitHub](https://github.com/).
5. Connect your local repository to GitHub and push:
   ```cmd
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   git push -u origin main
   ```
   *(Replace `YOUR_USERNAME` and `YOUR_REPO_NAME` with your actual GitHub parameters)*.

---

## Step 2: Configure the Web Service on Render

Render will read the `Dockerfile` in your repository and build the container automatically.

1. Go to the [Render Dashboard](https://dashboard.render.com/) and sign in.
2. Click **New +** (top right) and select **Web Service**.
3. Under **Connect a repository**, link your GitHub account and select your repository (`YOUR_REPO_NAME`).
4. In the configuration settings, fill in the following parameters:
   * **Name**: `cybershield-ncas` (or any custom name)
   * **Region**: Select the region closest to you (e.g., `Singapore` or `Oregon`)
   * **Branch**: `main`
   * **Root Directory**: *(Leave blank)*
   * **Runtime**: Select **Docker** (Render will automatically scan your `Dockerfile` for build instructions)
   * **Instance Type**: Select **Free**
5. Click **Deploy Web Service** at the bottom of the page.

---

## Step 3: Monitor and Verify Build Status

1. Render will initiate the build process. You can monitor the live compile logs in the Render console:
   * It will pull the base image (`python:3.11-slim`).
   * It will run `pip install -r requirements.txt`.
   * It will bind the application to container port `8080`.
2. Once the build log displays `Application startup complete` and status turns to **Live** (green), your portal is online!
3. Click the secure HTTPS URL provided at the top of the Render panel (e.g., `https://cybershield-ncas.onrender.com`) to access your portal.
