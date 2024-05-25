package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
  "github.com/dgrijalva/jwt-go"
	"time"
  "crypto/rand"
	"encoding/base64"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
  "io/ioutil"
  "fmt"
    "strconv"
)

var db *sql.DB
var jwtKey = []byte("your_secret_key") // Keep this key secret

type Thread struct {
    ID          int
    Title       string
    Description string
    Likes       int
    Dislikes    int
}
type Comment struct {
    Content  string
    Username string
}

func initDB(dataSourceName string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	// Read and execute SQL commands from schema.sql
	schema, err := ioutil.ReadFile("schema.sql")
	if err != nil {
		return nil, fmt.Errorf("error reading schema.sql: %w", err)
	}

	_, err = db.Exec(string(schema))
	if err != nil {
		return nil, fmt.Errorf("error executing schema.sql: %w", err)
	}

	log.Println("Database initialized successfully.")
	return db, nil
}

func main() {
  jwtKey = generateRandomKey(32)
  log.Println("JWT Key:", base64.StdEncoding.EncodeToString(jwtKey))

	var err error
  db, err = initDB("./forum.db")
  if err != nil {
      log.Fatalf("Error initializing database: %v", err)
  }
  defer db.Close()

	http.HandleFunc("/", serveHome)
	http.HandleFunc("/login", serveLogin)
	http.HandleFunc("/register", serveRegister)
	http.HandleFunc("/index", serveIndex)
	http.HandleFunc("/thread", serveThread)
  http.HandleFunc("/logout", serveLogout)
  http.HandleFunc("/login-guest", serveLoginGuest)
	http.HandleFunc("/create-thread", serveCreateThread)
  http.HandleFunc("/like-dislike", handleLikeDislike)
	http.HandleFunc("/comment", serveComment)
    http.HandleFunc("/comment-like-dislike", handleCommentLikeDislike)
	log.Fatal(http.ListenAndServe(":8080", nil))

	//log.Println("JWT Key:", base64.StdEncoding.EncodeToString(jwtKey))
}

func generateJWT(username string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "username": username,
        "exp":      time.Now().Add(time.Hour * 24).Unix(),
    })

    tokenString, err := token.SignedString(jwtKey)
    return tokenString, err
}


func generateRandomKey(length int) []byte {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal("Failed to generate random key:", err)
	}
	return key
}

func getUserIDByUsername(username string) (int, error) {
    var userID int
    err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
    if err != nil {
        return 0, err
    }
    return userID, nil
}


func serveLoginGuest(w http.ResponseWriter, r *http.Request) {
    // Generate a guest JWT token
    tokenString, err := generateJWT("guest")
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    // Set the token in a cookie
    http.SetCookie(w, &http.Cookie{
        Name:    "session_token",
        Value:   tokenString,
        Expires: time.Now().Add(24 * time.Hour),
        Path:    "/",
    })

    http.Redirect(w, r, "/index", http.StatusSeeOther)
}


func getUserFromSession(tokenString string) (string, int, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        username := claims["username"].(string)
        if username == "guest" {
            return username, 0, nil // Return 0 for userID if guest
        }
        userID, err := getUserIDByUsername(username)
        if err != nil {
            return "", 0, err
        }
        return username, userID, nil
    } else {
        return "", 0, err
    }
}

func serveHome(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("session_token")
    if err == nil && cookie.Value != "" {
        // Check if the session token is valid
        username, _, err := getUserFromSession(cookie.Value) // Ignore userID with '_'
        if err == nil && username != "" {
            http.Redirect(w, r, "/index", http.StatusSeeOther)
            return
        }
    }

    // If no valid session, show the home page with login and register options
    tmpl := template.Must(template.ParseFiles("templates/home.html"))
    tmpl.Execute(w, nil)
}

func getUserIDFromCookie(r *http.Request) (int, error) {
    cookie, err := r.Cookie("session_token")
    if err != nil {
        return 0, err
    }
    _, userID, err := getUserFromSession(cookie.Value)
    if err != nil {
        return 0, err
    }
    return userID, nil
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("session_token")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    username, _, err := getUserFromSession(cookie.Value) // Updated to use getUserFromSession
    if err != nil {
        http.Error(w, "Invalid session", http.StatusUnauthorized)
        return
    }

    rows, err := db.Query("SELECT id, title, description FROM threads")
    if err != nil {
        http.Error(w, "Failed to fetch threads", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var threads []Thread
    for rows.Next() {
        var t Thread
        if err := rows.Scan(&t.ID, &t.Title, &t.Description); err != nil {
            http.Error(w, "Failed to read thread data", http.StatusInternalServerError)
            return
        }
        threads = append(threads, t)
    }

    tmpl := template.Must(template.ParseFiles("templates/index.html"))
    tmpl.Execute(w, map[string]interface{}{
        "Username": username,
        "Threads":  threads,
    })
}

func serveThread(w http.ResponseWriter, r *http.Request) {
    threadID := r.URL.Query().Get("id")
    if threadID == "" {
        http.Error(w, "Thread ID is required", http.StatusBadRequest)
        return
    }

    var thread Thread
    var username string
    err := db.QueryRow(`
        SELECT t.id, t.title, t.description, t.likes, t.dislikes, u.username 
        FROM threads t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.id = ?`, threadID).Scan(&thread.ID, &thread.Title, &thread.Description, &thread.Likes, &thread.Dislikes, &username)
    if err != nil {
        http.Error(w, "Failed to fetch thread", http.StatusInternalServerError)
        return
    }

    // Fetch categories for the thread
    categoryRows, err := db.Query("SELECT c.name FROM categories c JOIN thread_categories tc ON c.id = tc.category_id WHERE tc.thread_id = ?", threadID)
    if err != nil {
        http.Error(w, "Failed to fetch categories", http.StatusInternalServerError)
        return
    }
    defer categoryRows.Close()

    var categories []string
    for categoryRows.Next() {
        var categoryName string
        if err := categoryRows.Scan(&categoryName); err != nil {
            http.Error(w, "Failed to read category data", http.StatusInternalServerError)
            return
        }
        categories = append(categories, categoryName)
    }

    cookie, err := r.Cookie("session_token")
    if err != nil {
        http.Error(w, "Failed to retrieve session data", http.StatusInternalServerError)
        return
    }
    
    username, _, err = getUserFromSession(cookie.Value) // Ignore userID with '_'
    if err != nil {
        http.Error(w, "Failed to validate session", http.StatusInternalServerError)
        return
    }
    isGuest := username == "guest"

    rows, err := db.Query("SELECT content, username FROM comments JOIN users ON users.id = comments.user_id WHERE thread_id = ?", threadID)
    if err != nil {
        http.Error(w, "Failed to fetch comments", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var comments []Comment
    for rows.Next() {
        var comment Comment
        if err := rows.Scan(&comment.Content, &comment.Username); err != nil {
            http.Error(w, "Failed to read comment data", http.StatusInternalServerError)
            return
        }
        comments = append(comments, comment)
    }

    tmpl := template.Must(template.ParseFiles("templates/thread.html"))
    tmpl.Execute(w, map[string]interface{}{
        "Thread":     thread,
        "Username":   username,
        "Categories": categories,
        "Comments":   comments,
        "IsGuest":    isGuest,
    })
}


func serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var hashedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Username not found", http.StatusUnauthorized)
			} else {
				http.Error(w, "Database error", http.StatusInternalServerError)
			}
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		// Generate JWT for the session
		tokenString, err := generateJWT(username)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Set the token in a cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   tokenString,
			Expires: time.Now().Add(24 * time.Hour),
			Path:    "/",
		})

		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	} else {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
	}
}


func serveLogout(w http.ResponseWriter, r *http.Request) {
	// Delete the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func serveRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error while hashing password", http.StatusInternalServerError)
			return
		}

		_, err = executeQuery("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", username, string(hashedPassword), email)
		if err != nil {
			http.Error(w, "Error while registering user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	} else {
		tmpl := template.Must(template.ParseFiles("templates/register.html"))
		tmpl.Execute(w, nil)
	}
}


func handleLikeDislike(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    threadID := r.FormValue("thread_id")
    likeTypeParam := r.FormValue("like_type") // This should be either "1" for like or "-1" for dislike
    likeType, err := strconv.Atoi(likeTypeParam)
    if err != nil || (likeType != 1 && likeType != -1) {
        http.Error(w, "Invalid like type", http.StatusBadRequest)
        return
    }

    userID, err := getUserIDFromCookie(r)
    if err != nil {
        http.Error(w, "Authentication error", http.StatusUnauthorized)
        return
    }

    // Start a transaction
    tx, err := db.Begin()
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer tx.Rollback()

    var existingType int
    err = tx.QueryRow("SELECT like_type FROM thread_likes WHERE thread_id = ? AND user_id = ?", threadID, userID).Scan(&existingType)
    if err != nil && err != sql.ErrNoRows {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    if existingType != 0 {
        http.Error(w, "You have already reacted to this thread", http.StatusForbidden)
        return
    }

    _, err = tx.Exec("INSERT INTO thread_likes (thread_id, user_id, like_type) VALUES (?, ?, ?)", threadID, userID, likeType)
    if err != nil {
        http.Error(w, "Failed to record reaction", http.StatusInternalServerError)
        return
    }

    if likeType == 1 {
        _, err = tx.Exec("UPDATE threads SET likes = likes + 1 WHERE id = ?", threadID)
    } else {
        _, err = tx.Exec("UPDATE threads SET dislikes = dislikes + 1 WHERE id = ?", threadID)
    }
    if err != nil {
        http.Error(w, "Failed to update thread", http.StatusInternalServerError)
        return
    }

    err = tx.Commit()
    if err != nil {
        http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/thread?id="+threadID, http.StatusSeeOther)
}

func serveCreateThread(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
        // Retrieve the session token from the cookie
        cookie, err := r.Cookie("session_token")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        // Decode the session token to check if the user is a guest
        username, userID, err := getUserFromSession(cookie.Value)
        if err != nil || username == "guest" {
            // If there's an error or the user is a guest, deny access
            http.Error(w, "Unauthorized access", http.StatusUnauthorized)
            return
        }

        // Proceed with creating the thread since the user is authenticated and not a guest
        title := r.FormValue("title")
        description := r.FormValue("description")
        categories := r.Form["categories"] 


        // Insert the new thread
        result, err := db.Exec("INSERT INTO threads (title, description, user_id) VALUES (?, ?, ?)", title, description, userID)
        if err != nil {
            http.Error(w, "Failed to create thread", http.StatusInternalServerError)
            return
        }

        // Get the last inserted thread ID
        threadID, err := result.LastInsertId()
        if err != nil {
            http.Error(w, "Failed to retrieve thread ID", http.StatusInternalServerError)
            return
        }

        // Insert category associations in the thread_categories table
        for _, catID := range categories {
            _, err = db.Exec("INSERT INTO thread_categories (thread_id, category_id) VALUES (?, ?)", threadID, catID)
            if err != nil {
                http.Error(w, "Failed to assign categories", http.StatusInternalServerError)
                return
            }
        }

        // Redirect to the index page after successful creation
        http.Redirect(w, r, "/index", http.StatusSeeOther)
    } else {
        // If the method is not POST, handle it as a bad request
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
    }
}


func serveComment(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
        threadID := r.FormValue("thread_id")
        comment := r.FormValue("comment")
        cookie, err := r.Cookie("session_token")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        username, _, err := getUserFromSession(cookie.Value) // Updated to use getUserFromSession
        if err != nil {
            http.Error(w, "Invalid session", http.StatusUnauthorized)
            return
        }

        _, err = db.Exec("INSERT INTO comments (content, user_id, thread_id) SELECT ?, id, ? FROM users WHERE username = ?", comment, threadID, username)
        if err != nil {
            http.Error(w, "Failed to post comment", http.StatusInternalServerError)
            return
        }
        http.Redirect(w, r, "/thread?id="+threadID, http.StatusSeeOther)
        return
    }
}

func handleCommentLikeDislike(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    commentID := r.FormValue("comment_id")
    likeTypeParam := r.FormValue("like_type")
    likeType, err := strconv.Atoi(likeTypeParam)
    if err != nil || (likeType != 1 && likeType != -1) {
        http.Error(w, "Invalid like type", http.StatusBadRequest)
        return
    }

    userID, err := getUserIDFromCookie(r)
    if err != nil {
        http.Error(w, "Authentication error", http.StatusUnauthorized)
        return
    }

    // Start a transaction
    tx, err := db.Begin()
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer tx.Rollback()

    var existingType int
    err = tx.QueryRow("SELECT like_type FROM comment_likes WHERE comment_id = ? AND user_id = ?", commentID, userID).Scan(&existingType)
    if err != nil && err != sql.ErrNoRows {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    if existingType != 0 {
        http.Error(w, "You have already reacted to this comment", http.StatusForbidden)
        return
    }

    _, err = tx.Exec("INSERT INTO comment_likes (comment_id, user_id, like_type) VALUES (?, ?, ?)", commentID, userID, likeType)
    if err != nil {
        http.Error(w, "Failed to record reaction", http.StatusInternalServerError)
        return
    }

    err = tx.Commit()
    if err != nil {
        http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/thread?id="+r.FormValue("thread_id"), http.StatusSeeOther)
}

func executeQuery(query string, args ...interface{}) (sql.Result, error) {
	return db.Exec(query, args...)
}

func queryRow(query string, args ...interface{}) *sql.Row {
	return db.QueryRow(query, args...)
}
//
