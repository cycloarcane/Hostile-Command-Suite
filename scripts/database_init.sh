# 1. Install PostgreSQL if not already installed
# On Arch:
sudo pacman -S postgresql
# On Ubuntu/Debian:
# sudo apt install postgresql

# 2. Initialize the database cluster if not already done
# On Arch:
sudo -u postgres initdb -D /var/lib/postgres/data
# On Ubuntu/Debian this happens automatically during installation

# 3. Start and enable PostgreSQL
sudo systemctl enable postgresql
sudo systemctl start postgresql

# 4. Create the database and user
sudo -u postgres psql -c "CREATE DATABASE osint_db;"
sudo -u postgres psql -c "CREATE USER osint_user WITH ENCRYPTED PASSWORD 'password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE osint_db TO osint_user;"

# 5. Set environment variables (add to your .bashrc or .zshrc for persistence)
export POSTGRES_DB=osint_db
export POSTGRES_USER=osint_user
export POSTGRES_PASSWORD=password
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432