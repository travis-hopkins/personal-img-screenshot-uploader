# 📸 Personal Image Screenshot Uploader

## Overview

The **Personal Image Screenshot Uploader** is a web application designed to upload, manage, and view screenshots. This app provides a user-friendly experience for uploading images, setting auto-deletion parameters, and securely managing your screenshots. It integrates with Google OAuth for seamless authentication.

## Features

- 🛡️ **User Authentication**: Secure login and registration using Google OAuth and local authentication.
- 📤 **Screenshot Upload**: Upload screenshots with unique filenames.
- 🗑️ **File Management**: Configure screenshots to auto-delete after a specified time or upon first view.
- 👁️ **User-specific Screenshots**: Users can view, delete, and manage their own screenshots.
- 🔧 **Admin Controls**: Admins can manage user roles and permissions.

## Technologies Used

- 🐍 **Flask**: Web framework for Python.
- 🗄️ **SQLAlchemy**: ORM for database management.
- 🔒 **Flask-Bcrypt**: For password hashing and verification.
- 🔑 **Flask-Login**: User session management.
- 📧 **Flask-Mail**: Sending emails for account activation.
- 🔐 **OAuth2**: Google OAuth for authentication.
- 🗃️ **SQLite**: Database for storing user and screenshot information.
- 💽 **dotenv**: Manage environment variables.

## Installation

### Prerequisites

- Python 3.x
- `pip` (Python package installer)
- `conda` or `virtualenv` (optional but recommended for virtual environments)

### Steps

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/personal-image-screenshot-uploader.git
   cd personal-image-screenshot-uploader
