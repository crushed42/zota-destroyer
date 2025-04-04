#!/bin/bash

# Script to install dependencies and then run the main application

# List of required packages
REQUIRED_PACKAGES=(
    "curl"
    "wget"
    "git"
    "build-essential"
    "python3"
    "python3-pip"
    "jq"
    "unzip"
    "htop"
)

# Function to check if a package is installed
is_package_installed() {
    dpkg -l "$1" &> /dev/null
    return $?
}

# Function to install packages
install_packages() {
    echo "Updating package lists..."
    sudo apt-get update -qq

    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if is_package_installed "$pkg"; then
            echo "✔ $pkg is already installed"
        else
            echo "Installing $pkg..."
            sudo apt-get install -y -qq "$pkg"
            if [ $? -eq 0 ]; then
                echo "✔ $pkg installed successfully"
            else
                echo "❌ Failed to install $pkg"
                exit 1
            fi
        fi
    done

    # Install Python packages if needed
    echo "Checking Python dependencies..."
    sudo pip3 install --upgrade pip
    sudo pip3 install requests bs4 numpy pandas
}

# Main function
main() {
    # Check if we're running as root
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script requires root privileges to install packages."
        echo "Please run with sudo or as root."
        exit 1
    fi

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        echo "Detected APT package manager"
        install_packages
    elif command -v yum &> /dev/null; then
        echo "Detected YUM package manager"
        # You would add yum installation commands here
        echo "YUM support not implemented in this script"
        exit 1
    elif command -v dnf &> /dev/null; then
        echo "Detected DNF package manager"
        # You would add dnf installation commands here
        echo "DNF support not implemented in this script"
        exit 1
    else
        echo "Unsupported package manager"
        exit 1
    fi

    echo "All dependencies installed successfully!"

    # Here you would call your main application script
    # ./your_main_script.sh
    echo "All prerequisites are now ready. You can run your main script."
}

# Execute main function
main "$@"
