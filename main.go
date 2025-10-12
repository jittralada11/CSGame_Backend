package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	UID      int    `json:"uid"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Image    string `json:"image"`
	Role     string `json:"role"`
	Created  string `json:"created_at"`
}

type GameType struct {
	TypeID   int    `json:"type_id"`
	TypeName string `json:"type_name"`
}

type Game struct {
	GameID      int     `json:"game_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	ReleaseDate string  `json:"release_date"`
	Sales       int     `json:"sales"`
	Price       float64 `json:"price"`
	Image       string  `json:"image"`
	TypeID      int     `json:"type_id"`
	TypeName    string  `json:"type_name,omitempty"`
}

type GameUpdate struct {
	GameID      int      `json:"game_id"`
	Name        *string  `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	ReleaseDate *string  `json:"release_date,omitempty"`
	Sales       *int     `json:"sales,omitempty"`
	Price       *float64 `json:"price,omitempty"`
	Image       *string  `json:"image,omitempty"`
	TypeID      *int     `json:"type_id,omitempty"`
}

type WalletTransaction struct {
	TransID     int     `json:"trans_id"`
	WalletID    int     `json:"wallet_id"`
	Amount      float64 `json:"amount"`
	TransType   string  `json:"trans_type"`
	Description string  `json:"description"`
	CreatedAt   string  `json:"created_at"`
	Username    string  `json:"username"`
}

// New struct types for enhanced functionality
type CartItem struct {
	CartID   int     `json:"cart_id"`
	UID      int     `json:"uid"`
	GameID   int     `json:"game_id"`
	GameName string  `json:"game_name"`
	Price    float64 `json:"price"`
	Image    string  `json:"image"`
	AddedAt  string  `json:"added_at"`
}

type Order struct {
	OrderID     int     `json:"order_id"`
	UID         int     `json:"uid"`
	Username    string  `json:"username"`
	TotalAmount float64 `json:"total_amount"`
	Status      string  `json:"status"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

type OrderItem struct {
	OrderItemID int     `json:"order_item_id"`
	OrderID     int     `json:"order_id"`
	GameID      int     `json:"game_id"`
	GameName    string  `json:"game_name"`
	Price       float64 `json:"price"`
	Quantity    int     `json:"quantity"`
}

type Review struct {
	ReviewID  int    `json:"review_id"`
	GameID    int    `json:"game_id"`
	UID       int    `json:"uid"`
	Username  string `json:"username"`
	Rating    int    `json:"rating"`
	Comment   string `json:"comment"`
	CreatedAt string `json:"created_at"`
}

type UserStats struct {
	UID           int     `json:"uid"`
	Username      string  `json:"username"`
	TotalOrders   int     `json:"total_orders"`
	TotalSpent    float64 `json:"total_spent"`
	GamesOwned    int     `json:"games_owned"`
	ReviewsCount  int     `json:"reviews_count"`
	WalletBalance float64 `json:"wallet_balance"`
}

var db *sql.DB

func main() {
	// ✅ ตั้งค่า DSN ของคุณ
	dsn := "66011212012:JittraladaDB2012@tcp(202.28.34.210:3309)/db66011212012"

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil { log.Fatal("Cannot connect to database:", err) }
	defer db.Close()

	if err = db.Ping(); err != nil { log.Fatal("Cannot ping database:", err) }
	fmt.Println("✅ Connected to database successfully")

	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "CSShop Backend-API is running successfully! ")
	})

	// Users
	mux.HandleFunc("/user", getUsers)
	// Users (commented out - need additional imports)
	mux.HandleFunc("/register", registerUser)
	mux.HandleFunc("/login", loginUser)
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/update-profile", updateUser)

	// Games & Types
	mux.HandleFunc("/game-type", addGameType) // POST
	mux.HandleFunc("/game-types", getGameTypes) // GET
	mux.HandleFunc("/game", gameHandler) // POST=add, PUT=update, DELETE=delete
	mux.HandleFunc("/games", getGames)   // GET list

	// Shopping Cart
	mux.HandleFunc("/cart", getCart)        // GET user's cart
	mux.HandleFunc("/cart/add", addToCart)  // POST add item to cart
	mux.HandleFunc("/cart/remove", removeFromCart) // DELETE remove item from cart

	// Orders
	mux.HandleFunc("/orders", getOrders)      // GET user's orders
	mux.HandleFunc("/order/create", createOrder) // POST create new order
	mux.HandleFunc("/order/status", updateOrderStatus) // PUT update order status

	// Reviews
	mux.HandleFunc("/reviews", getReviews)    // GET game reviews
	mux.HandleFunc("/review/add", addReview)  // POST add game review

	// User Statistics
	mux.HandleFunc("/user/stats", getUserStats) // GET user statistics

	// Static
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	handler := enableCORS(mux)

	ip := getLocalIP()
	url := fmt.Sprintf("http://%s:8080", ip)
	openBrowser(url)

	fmt.Printf("🚀 Server started at %s\n", url)
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", handler))
}

// ---------- Infra ----------
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == "OPTIONS" { w.WriteHeader(http.StatusOK); return }
		next.ServeHTTP(w, r)
	})
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs(); if err != nil { return "localhost" }
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip := ipnet.IP.To4(); ip != nil {
				if ip[0] == 192 || ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) { return ip.String() }
			}
		}
	}
	return "localhost"
}

func openBrowser(url string) {
	var cmd string; var args []string
	switch runtime.GOOS {
	case "windows": cmd = "rundll32"; args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin": cmd = "open"; args = []string{url}
	default: cmd = "xdg-open"; args = []string{url}
	}
	exec.Command(cmd, args...).Start()
}

// ---------- Game Routes Entrypoint ----------
func gameHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		addGame(w, r)
	case http.MethodPut:
		updateGame(w, r)
	case http.MethodDelete:
		deleteGame(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------- Game Type ----------
func addGameType(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "Method not allowed", http.StatusMethodNotAllowed); return }
	var gt struct{ TypeName string `json:"type_name"` }
	if err := json.NewDecoder(r.Body).Decode(&gt); err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }

	var exists int
	if err := db.QueryRow("SELECT COUNT(*) FROM game_type WHERE type_name = ?", gt.TypeName).Scan(&exists); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError); return
	}
	if exists > 0 { http.Error(w, "Game type already exists", http.StatusBadRequest); return }

	res, err := db.Exec("INSERT INTO game_type (type_name) VALUES (?)", gt.TypeName)
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	lastID, _ := res.LastInsertId()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Game type added successfully", "type_id": lastID, "type_name": gt.TypeName,
	})
}

func getGameTypes(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT type_id, type_name FROM game_type ORDER BY type_name")
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	defer rows.Close()

	var list []GameType
	for rows.Next() {
		var gt GameType
		if err := rows.Scan(&gt.TypeID, &gt.TypeName); err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
		list = append(list, gt)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

// ---------- Game ----------
func addGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "Method not allowed", http.StatusMethodNotAllowed); return }

	var g struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		ReleaseDate string  `json:"release_date"`
		Sales       int     `json:"sales"`
		Price       float64 `json:"price"`
		Image       string  `json:"image"`
		TypeID      int     `json:"type_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }

	var ok int
	if err := db.QueryRow("SELECT COUNT(*) FROM game_type WHERE type_id = ?", g.TypeID).Scan(&ok); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError); return
	}
	if ok == 0 { http.Error(w, "Game type not found", http.StatusBadRequest); return }

	res, err := db.Exec(`INSERT INTO game (name, description, release_date, sales, price, image, type_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		g.Name, g.Description, g.ReleaseDate, g.Sales, g.Price, g.Image, g.TypeID)
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	lastID, _ := res.LastInsertId()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Game added successfully",
		"game_id": lastID, "name": g.Name, "description": g.Description,
		"release_date": g.ReleaseDate, "sales": g.Sales, "price": g.Price,
		"image": g.Image, "type_id": g.TypeID,
	})
}

func getGames(w http.ResponseWriter, r *http.Request) {
	q := `
		SELECT g.game_id, g.name, g.description, g.release_date, g.sales, g.price,
		       IFNULL(g.image, ''), g.type_id, IFNULL(gt.type_name, '')
		FROM game g
		LEFT JOIN game_type gt ON g.type_id = gt.type_id
		ORDER BY g.name
	`
	rows, err := db.Query(q)
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	defer rows.Close()

	var list []Game
	for rows.Next() {
		var g Game
		if err := rows.Scan(&g.GameID, &g.Name, &g.Description, &g.ReleaseDate, &g.Sales, &g.Price, &g.Image, &g.TypeID, &g.TypeName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError); return
		}
		list = append(list, g)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func updateGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut { http.Error(w, "Method not allowed", http.StatusMethodNotAllowed); return }

	var in GameUpdate
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil { http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest); return }
	if in.GameID == 0 { http.Error(w, "game_id is required", http.StatusBadRequest); return }

	var cur Game
	err := db.QueryRow(`
		SELECT game_id, name, description, release_date, sales, price, IFNULL(image,''), type_id
		FROM game WHERE game_id = ?`, in.GameID).
		Scan(&cur.GameID, &cur.Name, &cur.Description, &cur.ReleaseDate, &cur.Sales, &cur.Price, &cur.Image, &cur.TypeID)
	if err != nil {
		if err == sql.ErrNoRows { http.Error(w, "Game not found", http.StatusNotFound); return }
		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError); return
	}

	if in.Name != nil { cur.Name = *in.Name }
	if in.Description != nil { cur.Description = *in.Description }
	if in.ReleaseDate != nil { cur.ReleaseDate = *in.ReleaseDate }
	if in.Sales != nil { cur.Sales = *in.Sales }
	if in.Price != nil { cur.Price = *in.Price }
	if in.Image != nil { cur.Image = *in.Image }
	if in.TypeID != nil {
		var ok int
		if err := db.QueryRow("SELECT COUNT(*) FROM game_type WHERE type_id = ?", *in.TypeID).Scan(&ok); err != nil {
			http.Error(w, "Type check error: "+err.Error(), http.StatusInternalServerError); return
		}
		if ok == 0 { http.Error(w, "Game type not found", http.StatusBadRequest); return }
		cur.TypeID = *in.TypeID
	}

	_, err = db.Exec(`UPDATE game SET name=?, description=?, release_date=?, sales=?, price=?, image=?, type_id=? WHERE game_id=?`,
		cur.Name, cur.Description, cur.ReleaseDate, cur.Sales, cur.Price, cur.Image, cur.TypeID, cur.GameID)
	if err != nil { http.Error(w, "Exec error: "+err.Error(), http.StatusInternalServerError); return }

	var out Game
	err = db.QueryRow(`
		SELECT g.game_id, g.name, g.description, g.release_date, g.sales, g.price,
		       IFNULL(g.image, ''), g.type_id, IFNULL(gt.type_name, '')
		FROM game g LEFT JOIN game_type gt ON g.type_id = gt.type_id
		WHERE g.game_id = ?`, cur.GameID).
		Scan(&out.GameID, &out.Name, &out.Description, &out.ReleaseDate, &out.Sales, &out.Price, &out.Image, &out.TypeID, &out.TypeName)
	if err != nil { http.Error(w, "Reload error: "+err.Error(), http.StatusInternalServerError); return }

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "Game updated successfully", "game": out})
}

func deleteGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete { http.Error(w, "Method not allowed", http.StatusMethodNotAllowed); return }

	idStr := r.URL.Query().Get("id")
	if idStr == "" { http.Error(w, "Missing id", http.StatusBadRequest); return }

	var id int
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil || id <= 0 {
		http.Error(w, "Invalid id", http.StatusBadRequest); return
	}

	var exists int
	if err := db.QueryRow("SELECT COUNT(*) FROM game WHERE game_id = ?", id).Scan(&exists); err != nil {
		http.Error(w, "Count error: "+err.Error(), http.StatusInternalServerError); return
	}
	if exists == 0 { http.Error(w, "Game not found", http.StatusNotFound); return }

	res, err := db.Exec("DELETE FROM game WHERE game_id = ?", id)
	if err != nil { http.Error(w, "Delete error: "+err.Error(), http.StatusInternalServerError); return }
	aff, _ := res.RowsAffected()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Game deleted successfully", "deleted_count": aff, "game_id": id,
	})
}

// ---------- Users (ตามของเดิมคุณ) ----------
func getUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT uid, username, email, IFNULL(image, ''), role, created_at FROM user")
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.UID, &u.Username, &u.Email, &u.Image, &u.Role, &u.Created); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError); return
		}
		users = append(users, u)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// ----- โค้ดเดิมสำหรับ register/login/upload/profile -----
// *คงของเดิมคุณไว้ตามที่ทำงานอยู่แล้ว*
// หมายเหตุ: ฟังก์ชันเหล่านี้ต้องการ import packages เพิ่มเติม
// เช่น "time", "golang.org/x/crypto/bcrypt", "context", "github.com/cloudinary/cloudinary-go/v2"
// และ "github.com/cloudinary/cloudinary-go/v2/api/uploader"
// ให้เพิ่ม import เหล่านี้กลับมาเมื่อต้องการใช้งานฟังก์ชันเหล่านี้

// func registerUser(w http.ResponseWriter, r *http.Request) { /* โค้ดเดิมของคุณ */ }
func registerUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Password hashing failed", http.StatusInternalServerError)
		return
	}

	// Insert user into database
	_, err = db.Exec("INSERT INTO user (username, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
		user.Username, user.Email, string(hashedPassword), user.Role, time.Now())
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}
// func loginUser(w http.ResponseWriter, r *http.Request)    { /* โค้ดเดิมของคุณ */ }
func loginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Get user from database
	var user User
	var hashedPassword string
	err := db.QueryRow("SELECT uid, username, email, image, role, password FROM user WHERE username = ?", 
		credentials.Username).Scan(&user.UID, &user.Username, &user.Email, &user.Image, &user.Role, &hashedPassword)
	
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"user":    user,
	})
}
// func uploadHandler(w http.ResponseWriter, r *http.Request) { /* โค้ดเดิมของคุณ */ }
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(10 << 20) // 10 MB limit
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Unable to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Initialize Cloudinary
	cld, err := cloudinary.NewFromParams("your_cloud_name", "your_api_key", "your_api_secret")
	if err != nil {
		http.Error(w, "Cloudinary initialization failed", http.StatusInternalServerError)
		return
	}

	// Upload to Cloudinary
	uploadResult, err := cld.Upload.Upload(context.Background(), file, uploader.UploadParams{
		PublicID: handler.Filename,
	})
	if err != nil {
		http.Error(w, "Upload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "File uploaded successfully",
		"url":     uploadResult.SecureURL,
	})
}
// func updateUser(w http.ResponseWriter, r *http.Request)   { /* โค้ดเดิมของคุณ */ }
func updateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var updateData struct {
		UID      int     `json:"uid"`
		Username *string `json:"username,omitempty"`
		Email    *string `json:"email,omitempty"`
		Image    *string `json:"image,omitempty"`
		Role     *string `json:"role,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}

	if updateData.Username != nil {
		setParts = append(setParts, "username = ?")
		args = append(args, *updateData.Username)
	}
	if updateData.Email != nil {
		setParts = append(setParts, "email = ?")
		args = append(args, *updateData.Email)
	}
	if updateData.Image != nil {
		setParts = append(setParts, "image = ?")
		args = append(args, *updateData.Image)
	}
	if updateData.Role != nil {
		setParts = append(setParts, "role = ?")
		args = append(args, *updateData.Role)
	}

	if len(setParts) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	// Add UID to args for WHERE clause
	args = append(args, updateData.UID)

	// Build proper query string
	query := "UPDATE user SET " + strings.Join(setParts, ", ") + " WHERE uid = ?"

	_, err := db.Exec(query, args...)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

// ✅ handler สำหรับแอดมิน ดูประวัติการเติมเงินทั้งหมด
func getWalletTransactions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query(`
		SELECT wt.trans_id, wt.wallet_id, wt.amount, wt.trans_type, wt.description, wt.created_at, u.username
		FROM wallet_transaction wt
		JOIN wallet w ON wt.wallet_id = w.wallet_id
		JOIN user u ON w.uid = u.uid
		ORDER BY wt.created_at DESC`)
	if err != nil {
		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var transactions []WalletTransaction
	for rows.Next() {
		var t WalletTransaction
		if err := rows.Scan(&t.TransID, &t.WalletID, &t.Amount, &t.TransType, &t.Description, &t.CreatedAt, &t.Username); err != nil {
			http.Error(w, "Scan error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		transactions = append(transactions, t)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(transactions)
}

// Shopping Cart Functions
func getCart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid := r.URL.Query().Get("uid")
	if uid == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT c.cart_id, c.uid, c.game_id, g.name, g.price, g.image, c.added_at
		FROM cart c
		JOIN games g ON c.game_id = g.game_id
		WHERE c.uid = ?
		ORDER BY c.added_at DESC
	`

	rows, err := db.Query(query, uid)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cartItems []CartItem
	for rows.Next() {
		var item CartItem
		err := rows.Scan(&item.CartID, &item.UID, &item.GameID, &item.GameName, &item.Price, &item.Image, &item.AddedAt)
		if err != nil {
			http.Error(w, "Error scanning cart items", http.StatusInternalServerError)
			return
		}
		cartItems = append(cartItems, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cartItems)
}

func addToCart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cartItem struct {
		UID    int `json:"uid"`
		GameID int `json:"game_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&cartItem); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if item already exists in cart
	var exists int
	checkQuery := "SELECT COUNT(*) FROM cart WHERE uid = ? AND game_id = ?"
	err := db.QueryRow(checkQuery, cartItem.UID, cartItem.GameID).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if exists > 0 {
		http.Error(w, "Item already in cart", http.StatusConflict)
		return
	}

	// Add item to cart
	insertQuery := "INSERT INTO cart (uid, game_id, added_at) VALUES (?, ?, NOW())"
	_, err = db.Exec(insertQuery, cartItem.UID, cartItem.GameID)
	if err != nil {
		http.Error(w, "Failed to add item to cart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Item added to cart successfully"})
}

func removeFromCart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cartItem struct {
		UID    int `json:"uid"`
		GameID int `json:"game_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&cartItem); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	deleteQuery := "DELETE FROM cart WHERE uid = ? AND game_id = ?"
	result, err := db.Exec(deleteQuery, cartItem.UID, cartItem.GameID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Item not found in cart", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Item removed from cart successfully"})
}

// Order Management Functions
func getOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid := r.URL.Query().Get("uid")
	if uid == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT o.order_id, o.uid, u.username, o.total_amount, o.status, o.created_at, o.updated_at
		FROM orders o
		JOIN users u ON o.uid = u.uid
		WHERE o.uid = ?
		ORDER BY o.created_at DESC
	`

	rows, err := db.Query(query, uid)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var order Order
		err := rows.Scan(&order.OrderID, &order.UID, &order.Username, &order.TotalAmount, &order.Status, &order.CreatedAt, &order.UpdatedAt)
		if err != nil {
			http.Error(w, "Error scanning orders", http.StatusInternalServerError)
			return
		}
		orders = append(orders, order)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orders)
}

func createOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var orderRequest struct {
		UID int `json:"uid"`
	}

	if err := json.NewDecoder(r.Body).Decode(&orderRequest); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Get cart items for the user
	cartQuery := `
		SELECT c.game_id, g.name, g.price
		FROM cart c
		JOIN games g ON c.game_id = g.game_id
		WHERE c.uid = ?
	`

	rows, err := db.Query(cartQuery, orderRequest.UID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cartItems []struct {
		GameID   int     `json:"game_id"`
		GameName string  `json:"game_name"`
		Price    float64 `json:"price"`
	}
	var totalAmount float64

	for rows.Next() {
		var item struct {
			GameID   int     `json:"game_id"`
			GameName string  `json:"game_name"`
			Price    float64 `json:"price"`
		}
		err := rows.Scan(&item.GameID, &item.GameName, &item.Price)
		if err != nil {
			http.Error(w, "Error scanning cart items", http.StatusInternalServerError)
			return
		}
		cartItems = append(cartItems, item)
		totalAmount += item.Price
	}

	if len(cartItems) == 0 {
		http.Error(w, "Cart is empty", http.StatusBadRequest)
		return
	}

	// Create order
	orderQuery := "INSERT INTO orders (uid, total_amount, status, created_at, updated_at) VALUES (?, ?, 'pending', NOW(), NOW())"
	result, err := db.Exec(orderQuery, orderRequest.UID, totalAmount)
	if err != nil {
		http.Error(w, "Failed to create order", http.StatusInternalServerError)
		return
	}

	orderID, _ := result.LastInsertId()

	// Create order items
	for _, item := range cartItems {
		orderItemQuery := "INSERT INTO order_items (order_id, game_id, price, quantity) VALUES (?, ?, ?, 1)"
		_, err := db.Exec(orderItemQuery, orderID, item.GameID, item.Price)
		if err != nil {
			http.Error(w, "Failed to create order items", http.StatusInternalServerError)
			return
		}
	}

	// Clear cart
	clearCartQuery := "DELETE FROM cart WHERE uid = ?"
	_, err = db.Exec(clearCartQuery, orderRequest.UID)
	if err != nil {
		http.Error(w, "Failed to clear cart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Order created successfully",
		"order_id":     orderID,
		"total_amount": totalAmount,
	})
}

func updateOrderStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var statusUpdate struct {
		OrderID int    `json:"order_id"`
		Status  string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&statusUpdate); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate status
	validStatuses := []string{"pending", "processing", "shipped", "delivered", "cancelled"}
	isValid := false
	for _, status := range validStatuses {
		if statusUpdate.Status == status {
			isValid = true
			break
		}
	}

	if !isValid {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	updateQuery := "UPDATE orders SET status = ?, updated_at = NOW() WHERE order_id = ?"
	result, err := db.Exec(updateQuery, statusUpdate.Status, statusUpdate.OrderID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Order not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Order status updated successfully"})
}

// Review System Functions
func getReviews(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	gameID := r.URL.Query().Get("game_id")
	if gameID == "" {
		http.Error(w, "Game ID is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT r.review_id, r.game_id, r.uid, u.username, r.rating, r.comment, r.created_at
		FROM reviews r
		JOIN users u ON r.uid = u.uid
		WHERE r.game_id = ?
		ORDER BY r.created_at DESC
	`

	rows, err := db.Query(query, gameID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var reviews []Review
	for rows.Next() {
		var review Review
		err := rows.Scan(&review.ReviewID, &review.GameID, &review.UID, &review.Username, &review.Rating, &review.Comment, &review.CreatedAt)
		if err != nil {
			http.Error(w, "Error scanning reviews", http.StatusInternalServerError)
			return
		}
		reviews = append(reviews, review)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reviews)
}

func addReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var review struct {
		GameID  int    `json:"game_id"`
		UID     int    `json:"uid"`
		Rating  int    `json:"rating"`
		Comment string `json:"comment"`
	}

	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate rating
	if review.Rating < 1 || review.Rating > 5 {
		http.Error(w, "Rating must be between 1 and 5", http.StatusBadRequest)
		return
	}

	// Check if user already reviewed this game
	var exists int
	checkQuery := "SELECT COUNT(*) FROM reviews WHERE uid = ? AND game_id = ?"
	err := db.QueryRow(checkQuery, review.UID, review.GameID).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if exists > 0 {
		http.Error(w, "User has already reviewed this game", http.StatusConflict)
		return
	}

	// Add review
	insertQuery := "INSERT INTO reviews (game_id, uid, rating, comment, created_at) VALUES (?, ?, ?, ?, NOW())"
	result, err := db.Exec(insertQuery, review.GameID, review.UID, review.Rating, review.Comment)
	if err != nil {
		http.Error(w, "Failed to add review", http.StatusInternalServerError)
		return
	}

	reviewID, _ := result.LastInsertId()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Review added successfully",
		"review_id": reviewID,
	})
}

// User Statistics Function
func getUserStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid := r.URL.Query().Get("uid")
	if uid == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	var stats UserStats

	// Get basic user info
	userQuery := "SELECT uid, username FROM users WHERE uid = ?"
	err := db.QueryRow(userQuery, uid).Scan(&stats.UID, &stats.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Get total orders and total spent
	orderQuery := `
		SELECT COUNT(*) as total_orders, COALESCE(SUM(total_amount), 0) as total_spent
		FROM orders 
		WHERE uid = ? AND status != 'cancelled'
	`
	err = db.QueryRow(orderQuery, uid).Scan(&stats.TotalOrders, &stats.TotalSpent)
	if err != nil {
		stats.TotalOrders = 0
		stats.TotalSpent = 0
	}

	// Get games owned (from completed orders)
	gamesQuery := `
		SELECT COUNT(DISTINCT oi.game_id) as games_owned
		FROM order_items oi
		JOIN orders o ON oi.order_id = o.order_id
		WHERE o.uid = ? AND o.status = 'delivered'
	`
	err = db.QueryRow(gamesQuery, uid).Scan(&stats.GamesOwned)
	if err != nil {
		stats.GamesOwned = 0
	}

	// Get reviews count
	reviewQuery := "SELECT COUNT(*) as reviews_count FROM reviews WHERE uid = ?"
	err = db.QueryRow(reviewQuery, uid).Scan(&stats.ReviewsCount)
	if err != nil {
		stats.ReviewsCount = 0
	}

	// Get wallet balance (assuming there's a wallet table)
	walletQuery := "SELECT COALESCE(balance, 0) as wallet_balance FROM wallet WHERE uid = ?"
	err = db.QueryRow(walletQuery, uid).Scan(&stats.WalletBalance)
	if err != nil {
		stats.WalletBalance = 0
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
