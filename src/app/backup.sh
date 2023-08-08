#!/bin/sh

# shellcheck disable=SC1091

. /opt/scripts/logging.sh
. /opt/scripts/set-env.sh
: "${warning_counter:=0}"
: "${error_counter:=0}"


### Functions ###
# Generate a single SHA256 hash of the contents of a tar file
generate_tarfile_contenthash() {
  source_file="$1"
  TEMP_EXTRACTION_FOLDER=/tmp/extracted

  mkdir -p $TEMP_EXTRACTION_FOLDER
  # Generate hash
  if eval /bin/tar -xf "$source_file" -C "$TEMP_EXTRACTION_FOLDER"; then
    result="$(find $TEMP_EXTRACTION_FOLDER -type f -exec sha256sum {} + | LC_ALL=C sort | sha256sum | awk '{print $1}')"
    echo "$result"
  else
    debug "Successfully created backup $BACKUP_FILE_ARCHIVE"
  fi
  rm -rf "$TEMP_EXTRACTION_FOLDER"
}


# Initialize variables
init() {
  if [ "$TIMESTAMP" = true ]; then
    TIMESTAMP_PREFIX="$(date "+%F-%H%M%S")_"
  fi

  TEMP_BACKUP_ARCHIVE="/tmp/temp-backup.tar.xz"
  BACKUP_FILE_DB=/tmp/db.sqlite3
  BACKUP_FILE_ARCHIVE="$BACKUP_DIR/${TIMESTAMP_PREFIX}backup.tar.xz"

    if [ ! -f "$VW_DATABASE_URL" ]; then
      printf 1 > "$HEALTHCHECK_FILE"
      critical "Database $VW_DATABASE_URL not found! Please check if you mounted the vaultwarden volume (in docker-compose or with '--volumes-from=vaultwarden'!)"
  fi
}

# Backup database and additional data like attachments, sends, etc.
backup() {
  tar_file_params=""
  # First we backup the database to a temporary file (this will later be added to a tar archive)
  if [ "$BACKUP_ADD_DATABASE" = true ] && /usr/bin/sqlite3 "$VW_DATABASE_URL" ".backup '$BACKUP_FILE_DB'"; then
    tar_file_params="$tar_file_params -C $(dirname "$(readlink -f $BACKUP_FILE_DB)") $(basename $BACKUP_FILE_DB)"
    # Mirror timestamp of source database
    touch "$BACKUP_FILE_DB" -r "$VW_DATABASE_URL"

    debug "Written temporary backup file to $BACKUP_FILE_DB"
    debug "Current tar command: $tar_file_params"
  else
    error "Backup of the database failed"
  fi

  # We use this technique to simulate an array in a POSIX compliant way
  if [ "$BACKUP_ADD_ATTACHMENTS" = true ] && [ -e "$VW_ATTACHMENTS_FOLDER" ]; then tar_file_params="$tar_file_params -C $(dirname "$(readlink -f "$VW_ATTACHMENTS_FOLDER")") $(basename "$VW_ATTACHMENTS_FOLDER")"; fi
  if [ "$BACKUP_ADD_ICON_CACHE" = true ] && [ -e "$VW_ICON_CACHE_FOLDER" ]; then tar_file_params="$tar_file_params -C $(dirname "$(readlink -f "$VW_ICON_CACHE_FOLDER")") $(basename "$VW_ICON_CACHE_FOLDER")"; fi
  if [ "$BACKUP_ADD_SENDS" = true ] && [ -e "$VW_DATA_FOLDER/sends" ]; then tar_file_params="$tar_file_params -C $(dirname "$(readlink -f "$VW_DATA_FOLDER/sends")") $(basename "$VW_DATA_FOLDER/sends")"; fi
  if [ "$BACKUP_ADD_CONFIG_JSON" = true ] && [ -e "$VW_DATA_FOLDER/config.json" ]; then tar_file_params="$tar_file_params -C $(dirname "$(readlink -f "$VW_DATA_FOLDER/config.json")") $(basename "$VW_DATA_FOLDER/config.json")"; fi
  if [ "$BACKUP_ADD_RSA_KEY" = true ]; then
    rsa_keys="$(find "$VW_DATA_FOLDER" -iname 'rsa_key*')"
    debug "found RSA keys: $rsa_keys"
    for rsa_key in $rsa_keys; do
      tar_file_params="$tar_file_params -C $(dirname "$(readlink -f "$rsa_key")") $(basename "$rsa_key")"
    done
  fi

  debug "Current tar command: /bin/tar -cJf $BACKUP_FILE_ARCHIVE $tar_file_params"

  # Placeholders
  create_new_backup=true           # By default, create a new backup
  latest_backup_contenthash=""
  previous_backup_file=""
  previous_backup_hashcheck_file=""
  backup_file_searchstring="*backup.tar.xz"    # search for previous backup files matching these patterns

  # Create a temporary unencrypted backup file
  if eval /bin/tar -cJf "$TEMP_BACKUP_ARCHIVE" "$tar_file_params"; then
    # Generate a filehash of the backup for future comparison
    latest_backup_contenthash="$(generate_tarfile_contenthash $TEMP_BACKUP_ARCHIVE)"
  else
    error "Backup failed"
  fi

  # Get the name of the previous backup file and set the backup filename for encrypted files 
  if [ -f "$ENCRYPTION_GPG_KEYFILE_LOCATION" ] || [ ! "$ENCRYPTION_PASSWORD" = false ]; then
    backup_file_searchstring="${backup_file_searchstring}.gpg"
    BACKUP_FILE_ARCHIVE="$BACKUP_FILE_ARCHIVE.gpg"
  fi

  # If DEDUPE is enabled, check if there are any changes from the previous and current backup files
  if [ "$BACKUP_USE_DEDUPE" = true ]; then
    debug "Dedupe switch detected.  Checking for previous backups."
    # Find the latest previous backup file
    previous_backup_file="$(find "${BACKUP_DIR}" -type f -name "${backup_file_searchstring}" -print0 | xargs -0 ls -tr | tail -n 1)"
    previous_backup_hashcheck_file="$BACKUP_DIR/$(basename "${previous_backup_file}").hash"

    # Only proceed if previous backup and hashcheck files exist
    if [ -f "$previous_backup_file" ] && [ -f "$previous_backup_hashcheck_file" ]; then
      debug "Previous backup and corresponding hascheck file detected"
      debug "Evaluating previous backup: $previous_backup_file"
      # Generate a filehash of the tar file for comparison
      previous_backup_tarhash="$(sha256sum $previous_backup_file | awk '{print $1}')"

      # Extract the previous tar filehash (1st line)
      extracted_tarhash="$(head -n 1 $previous_backup_hashcheck_file)"

      # Ensure the hash of the latest backup file matches the extracted tarhash!
      if [ "$extracted_tarhash" = "$previous_backup_tarhash" ]; then
        debug "Previous backup matches expected hash.  Checking contents"
        # Extract the 2nd line of the hasheck file (line 2)
        extracted_contenthash="$(sed -n '2p' < $previous_backup_hashcheck_file)"

        # Check if the content of the latest backup file matches the previous backup!
        if [ $extracted_contenthash = $latest_backup_contenthash ]; then
          debug "Tar contents match.  No changes detected since last backup"
          create_new_backup=false
        fi
      fi
    fi
  fi


  # Here we create the backup tar archive with optional encryption
  if [ "$ENCRYPTION_BASE64_GPG_KEY" != false ] && [ "$ENCRYPTION_PASSWORD" != false ]; then
    warn "Ignoring ENCRYPTION_PASSWORD since you set both ENCRYPTION_BASE64_GPG_KEY and ENCRYPTION_PASSWORD."
  fi

  if [ -f "$ENCRYPTION_GPG_KEYFILE_LOCATION" ]; then
    debug "Encrypting using GPG Keyfile"

    # If DEDUPE is enabled and previous backup exists, check if the key has changed
    if [ "$BACKUP_USE_DEDUPE" = true ] && [ -f "$previous_backup_file" ] && [ "$create_new_backup" = false ]; then
      debug "Previous backup detected.  Checking to see if the key has changed"
      # Get KeyID of current GPG Keyfile
      current_keyID="$(gpg --with-colons "$ENCRYPTION_GPG_KEYFILE_LOCATION" 2>&1 | awk -F':' '/sub/{ print $5 }')"

      # Get public KeyID of previous backup
      previous_keyID="$(gpg --pinentry-mode cancel --list-packets "$previous_backup_file" 2>&1 | sed -n 's/.*:pubkey\s.*\skeyid \(.*\)$/\1/p')"

      # Check if the key IDs  match.  If not, create a new backup.
      if [ "$current_keyID" != "$previous_keyID" ]; then create_new_backup=true; fi
    fi

    #Check if create new backup flag is enabled or dedupe is disabled
    if [ "$create_new_backup" = true ] || [ "$BACKUP_USE_DEDUPE" = false ]; then
      debug "Creating new backup file"
      # Create a backup with public key encryption
      if eval gpg --batch --no-options --no-tty --yes --recipient-file "$ENCRYPTION_GPG_KEYFILE_LOCATION"\
          -o "$BACKUP_FILE_ARCHIVE" --encrypt "$TEMP_BACKUP_ARCHIVE"; then
        info "Successfully created gpg (public key) encrypted backup $BACKUP_FILE_ARCHIVE"
      else
        error "Encrypted backup failed!"
      fi
    else
      # If the latest backup is UNCHANGED form the previous backup and dedupe is enabled, copy previous backup file.
      debug "No changes detected since last backup. Dedupe enabled.  Copying previous backup."
      if eval cp "$previous_backup_file" "$BACKUP_FILE_ARCHIVE"; then
        touch -a -m "$BACKUP_FILE_ARCHIVE"
        info "Successfully copied previous backup"
      else
        error "Failed to copy previous backup!"
      fi
    fi

  elif [ ! "$ENCRYPTION_PASSWORD" = false ]; then
    debug "Creating backup using passphrase"

    # If DEDUPE is enabled and a previous backup exists, check if the key has changed
    if [ "$BACKUP_USE_DEDUPE" = true ] && [ -f "$previous_backup_file" ] && [ "$create_new_backup" = false ]; then
      debug "Previous backup detected.  Checking to see if the passphrase has changed"

      # Attempt to decrypt previous backup with current key
      if gpg --decrypt --batch --dry-run --output /dev/null --passphrase "$ENCRYPTION_PASSWORD" "$previous_backup_file"; then
        # Previous backup key is correct
        debug "Passphrase is unchanged."
      else
        debug "Passphrase has changed since the last backup!  A new backup will be created"
        create_new_backup=true
      fi
    fi

    #Check if content has changed and dedupe is enabled
    if [ "$create_new_backup" = true ] || [ "$BACKUP_USE_DEDUPE" = false ]; then
      # Create a backup with symmetric encryption
      debug "Creating backup with symmetric encryption"
      if gpg --batch --no-options --no-tty --yes --symmetric --passphrase "$ENCRYPTION_PASSWORD" \
           --cipher-algo "$ENCRYPTION_ALGORITHM" -o "$BACKUP_FILE_ARCHIVE" "$TEMP_BACKUP_ARCHIVE"; then
        info "Successfully created gpg (password) encrypted backup $BACKUP_FILE_ARCHIVE"
      else
        error "Encrypted backup failed!"
      fi
    else
      # If the latest backup is UNCHANGED form the previous backup and dedupe is enabled, copy previous backup file.
      debug "No changes detected since last backup. Dedupe enabled.  Copying previous backup."
      if eval cp "$previous_backup_file" "$BACKUP_FILE_ARCHIVE"; then
        touch -a -m "$BACKUP_FILE_ARCHIVE"
        info "Successfully copied previous backup"
      else
        error "Failed to copy previous backup!"
      fi
    fi

  else
    # Create a backup without encryption
    debug "Creating backup without encryption"

    # If DEDUPE is enabled, a previous backup exists, and the contents have NOT changed, then copy the previous backup 
    if [ "$BACKUP_USE_DEDUPE" = true ] && [ -f "$previous_backup_file" ] && [ "$create_new_backup" = false ]; then
      debug "No changes detected since last backup. Dedupe enabled.  Copying previous backup."
      if eval cp "$previous_backup_file" "$BACKUP_FILE_ARCHIVE"; then
        touch -a -m "$BACKUP_FILE_ARCHIVE"
        info "Successfully copied previous backup"
      else
        error "Failed to copy previous backup!"
      fi
    else
      debug "Changes detected since last backup.  Creating new backup file."
      if eval cp "$TEMP_BACKUP_ARCHIVE" "$BACKUP_FILE_ARCHIVE"; then
        touch -a -m "$BACKUP_FILE_ARCHIVE"
        info "Successfully created  backup"
      else
        error "Failed to create backup!"
      fi
    fi
  fi

  # Remove temporary files and old
  rm "$BACKUP_FILE_DB"
  rm "$previous_backup_hashcheck_file"
  rm "$TEMP_BACKUP_ARCHIVE"


  # Generate a new hash check file If dedupe is enabled
  if [ "$BACKUP_USE_DEDUPE" = true ]; then
    debug "Generating new backup hashcheck file"

    LATEST_BACKUP_HASHCHECK_FILE="$BACKUP_FILE_ARCHIVE.hash"
    touch "$LATEST_BACKUP_HASHCHECK_FILE"

    # Calculate the current backup
    latest_backup_tarhash="$(sha256sum $BACKUP_FILE_ARCHIVE | awk '{print $1}')"

    # Copy the latest hash data
    echo "$latest_backup_tarhash" >> "$LATEST_BACKUP_HASHCHECK_FILE"
    echo "$latest_backup_contenthash" >> "$LATEST_BACKUP_HASHCHECK_FILE"
  fi

}

# Performs a healthcheck
perform_healthcheck() {
  debug "\$error_counter=$error_counter"

  if [ "$error_counter" -ne 0 ]; then
    warn "There were $error_counter errors during backup. Not sending health check ping."
    printf 1 > "$HEALTHCHECK_FILE"
    return 1
  fi

  # At this point the container is healthy. So we create a health-check file used to determine container health
  # and send a health check ping if the HEALTHCHECK_URL is set.
  printf 0 > "$HEALTHCHECK_FILE"
  debug "Evaluating \$HEALTHCHECK_URL"
  if [ -z "$HEALTHCHECK_URL" ]; then
    debug "Variable \$HEALTHCHECK_URL not set. Skipping health check."
    return 0
  fi

  info "Sending health check ping."
  wget "$HEALTHCHECK_URL" -T 10 -t 5 -q -O /dev/null
}

cleanup() {
  if [ -n "$DELETE_AFTER" ] && [ "$DELETE_AFTER" -gt 0 ]; then
    if [ "$TIMESTAMP" != true ]; then warn "DELETE_AFTER will most likely have no effect because TIMESTAMP is not set to true."; fi
    find "$BACKUP_DIR" -type f -mtime +"$DELETE_AFTER" -exec sh -c '. /opt/scripts/logging.sh; file="$1"; rm -f "$file"; info "Deleted backup "$file" after $DELETE_AFTER days"' shell {} \;
  fi
}

### Main ###

# Run init
init

# Run the backup command
backup

# Perform healthcheck
perform_healthcheck

# Delete backup files after $DELETE_AFTER days.
cleanup
