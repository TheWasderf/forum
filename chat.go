package main

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "time"
)

func messageHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        currentUser, err := getCurrentUser(r) // Assuming getCurrentUser returns (string, error)
        if err != nil {
            http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
            return
        }

        if currentUser == "guest" {
            http.Error(w, "Unauthorized access for guest user", http.StatusUnauthorized)
            return
        }

        switch r.Method {
        case "GET":
            handleGetMessages(w, db, currentUser)
        case "POST":
            handlePostMessage(w, r, db)
        default:
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        }
    }
}

func handleGetMessages(w http.ResponseWriter, db *sql.DB, currentUser string) {
    query := `SELECT id, Username, recipient, content, time FROM messages WHERE recipient = ?`
    rows, err := db.Query(query, currentUser)
    if err != nil {
        http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var messages []Message
    for rows.Next() {
        var message Message
        if err := rows.Scan(&message.ID, &message.Username, &message.Recipient, &message.Content, &message.Time); err != nil {
            http.Error(w, "Scan error: "+err.Error(), http.StatusInternalServerError)
            return
        }
        messages = append(messages, message)
    }

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(messages); err != nil {
        http.Error(w, "JSON encoding error: "+err.Error(), http.StatusInternalServerError)
        return
    }
}

func handlePostMessage(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    var message Message
    if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
        http.Error(w, "JSON decode error: "+err.Error(), http.StatusBadRequest)
        return
    }
    message.Time = time.Now()

    _, err := db.Exec("INSERT INTO messages (Username, recipient, content, time) VALUES (?, ?, ?, ?)",
        message.Username, message.Recipient, message.Content, message.Time)
    if err != nil {
        http.Error(w, "Insert error: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    if err := json.NewEncoder(w).Encode(message); err != nil {
        http.Error(w, "JSON encoding error: "+err.Error(), http.StatusInternalServerError)
        return
    }
}