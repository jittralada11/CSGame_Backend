// package main

// import (
// 	"context"
// 	"database/sql"
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net"
// 	"net/http"
// 	"os/exec"
// 	"runtime"
// 	"time"

// 	"github.com/cloudinary/cloudinary-go/v2"
// 	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
// 	_ "github.com/go-sql-driver/mysql"
// 	"golang.org/x/crypto/bcrypt"
// )

// // กำหนดโครงสร้างข้อมูล user (ตรงกับ table user)
// type User struct {
// 	UID      int    `json:"uid"`
// 	Username string `json:"username"`
// 	Email    string `json:"email"`
// 	Image    string `json:"image"`
// 	Role     string `json:"role"`
// 	Created  string `json:"created_at"`
// }

// // โครงสร้างข้อมูล Wallet และ Transaction
// type Wallet struct {
// 	WalletID    int     `json:"wallet_id"`
// 	UID         int     `json:"uid"`
// 	Balance     float64 `json:"balance"`
// 	LastUpdated string  `json:"last_updated"`
// }

// type WalletTransaction struct {
// 	TransID     int     `json:"trans_id"`
// 	WalletID    int     `json:"wallet_id"`
// 	Amount      float64 `json:"amount"`
// 	TransType   string  `json:"trans_type"`
// 	Description string  `json:"description"`
// 	CreatedAt   string  `json:"created_at"`
// 	Username    string  `json:"username,omitempty"` // สำหรับหน้าแอดมิน
// }

// var db *sql.DB

// func main() {
// 	// Connection string
// 	dsn := "66011212012:JittraladaDB2012@tcp(202.28.34.210:3309)/db66011212012"

// 	var err error
// 	db, err = sql.Open("mysql", dsn)
// 	if err != nil {
// 		log.Fatal("Cannot connect to database:", err)
// 	}
// 	defer db.Close()

// 	if err = db.Ping(); err != nil {
// 		log.Fatal("Cannot ping database:", err)
// 	}
// 	fmt.Println("✅ Connected to database successfully")

// 	// Router
// 	mux := http.NewServeMux()
// 	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
// 		fmt.Fprintln(w, "CSShop Backend-API is running successfully! ")
// 	})
// 	mux.HandleFunc("/user", getUsers)
// 	mux.HandleFunc("/register", registerUser)
// 	mux.HandleFunc("/login", loginUser)
// 	mux.HandleFunc("/upload", uploadHandler)
// 	mux.HandleFunc("/update-profile", updateUser)
// 	mux.HandleFunc("/wallet/topup", topUpWallet)
// 	mux.HandleFunc("/wallet/transactions", getWalletTransactions)

// 	// ✅ Serve static files (รูป)
// 	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

// 	// ✅ เปิด CORS ให้ Angular เรียกได้
// 	handler := enableCORS(mux)

// 	// หา IP ของเครื่อง
// 	ip := getLocalIP()
// 	url := fmt.Sprintf("http://%s:8080", ip)

// 	// เปิด browser อัตโนมัติ
// 	openBrowser(url)

// 	// run server
// 	fmt.Printf("🚀 Server started at %s\n", url)
// 	log.Fatal(http.ListenAndServe("0.0.0.0:8080", handler))
// }

// // ✅ ฟังก์ชันเปิด CORS
// func enableCORS(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Access-Control-Allow-Origin", "*")
// 		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
// 		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
// 		if r.Method == "OPTIONS" {
// 			w.WriteHeader(http.StatusOK)
// 			return
// 		}
// 		next.ServeHTTP(w, r)
// 	})
// }

// // handler ดึงข้อมูล user ทั้งหมด
// func getUsers(w http.ResponseWriter, r *http.Request) {
// 	rows, err := db.Query("SELECT uid, username, email, IFNULL(image, ''), role, created_at FROM user")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer rows.Close()

// 	var users []User
// 	for rows.Next() {
// 		var u User
// 		if err := rows.Scan(&u.UID, &u.Username, &u.Email, &u.Image, &u.Role, &u.Created); err != nil {
// 			http.Error(w, err.Error(), http.StatusInternalServerError)
// 			return
// 		}
// 		users = append(users, u)
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(users)
// }

// // หา IPv4 LAN จริง
// func getLocalIP() string {
// 	addrs, err := net.InterfaceAddrs()
// 	if err != nil {
// 		return "localhost"
// 	}
// 	for _, addr := range addrs {
// 		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
// 			if ip := ipnet.IP.To4(); ip != nil {
// 				if ip[0] == 192 || ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
// 					return ip.String()
// 				}
// 			}
// 		}
// 	}
// 	return "localhost"
// }

// // เปิด browser อัตโนมัติ
// func openBrowser(url string) {
// 	var cmd string
// 	var args []string

// 	switch runtime.GOOS {
// 	case "windows":
// 		cmd = "rundll32"
// 		args = []string{"url.dll,FileProtocolHandler", url}
// 	case "darwin": // MacOS
// 		cmd = "open"
// 		args = []string{url}
// 	default: // Linux
// 		cmd = "xdg-open"
// 		args = []string{url}
// 	}

// 	exec.Command(cmd, args...).Start()
// }

// // handler ลงทะเบียนผู้ใช้ใหม่
// func registerUser(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var u struct {
// 		Username string `json:"username"`
// 		Email    string `json:"email"`
// 		Password string `json:"password"`
// 		Image    string `json:"image"` // ✅ URL ที่ส่งมาจาก Angular
// 		Role     string `json:"role"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// ตรวจสอบ email ซ้ำ
// 	var exists int
// 	err := db.QueryRow("SELECT COUNT(*) FROM user WHERE email = ?", u.Email).Scan(&exists)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	if exists > 0 {
// 		http.Error(w, "Email already exists", http.StatusBadRequest)
// 		return
// 	}

// 	// Hash password
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// ✅ ใช้ URL ที่ Angular ส่งมาเลย (ไม่อัปโหลดซ้ำ)
// 	imageURL := u.Image

// 	// INSERT ข้อมูลลงฐานข้อมูล
// 	stmt, err := db.Prepare("INSERT INTO user (username, email, password, image, role, created_at) VALUES (?, ?, ?, ?, ?, NOW())")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer stmt.Close()

// 	res, err := stmt.Exec(u.Username, u.Email, string(hashedPassword), imageURL, u.Role)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	lastID, _ := res.LastInsertId()

// 	// ✅ ส่งข้อมูลกลับไปที่ frontend
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"message":   "User registered successfully",
// 		"uid":       lastID,
// 		"username":  u.Username,
// 		"email":     u.Email,
// 		"role":      u.Role,
// 		"image":     imageURL,
// 		"createdAt": time.Now().Format("2006-01-02 15:04:05"),
// 	})
// }

// // handler สำหรับ login
// func loginUser(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var input struct {
// 		Email    string `json:"email"`
// 		Password string `json:"password"`
// 	}
// 	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	var hashedPassword, username, role, image, createdAt string
// 	var uid int

// 	// ✅ ดึง image และ created_at มาด้วย
// 	err := db.QueryRow("SELECT uid, username, password, role, IFNULL(image,''), created_at FROM user WHERE email = ?",
// 		input.Email).Scan(&uid, &username, &hashedPassword, &role, &image, &createdAt)

// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			http.Error(w, "Email not found", http.StatusUnauthorized)
// 			return
// 		}
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// ตรวจสอบ password
// 	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(input.Password))
// 	if err != nil {
// 		http.Error(w, "Incorrect password", http.StatusUnauthorized)
// 		return
// 	}

// 	// ✅ ตอบกลับ JSON ครบทุกฟิลด์
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"message":   "Login successful",
// 		"uid":       uid,
// 		"username":  username,
// 		"email":     input.Email,
// 		"role":      role,
// 		"image":     image,
// 		"createdAt": createdAt,
// 	})
// }

// // handler สำหรับอัปโหลดไฟล์
// func uploadHandler(w http.ResponseWriter, r *http.Request) {
// 	// อนุญาตเฉพาะ POST
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// อ่านไฟล์จากฟอร์ม
// 	file, header, err := r.FormFile("file")
// 	if err != nil {
// 		http.Error(w, "ไม่พบไฟล์ในคำขอ", http.StatusBadRequest)
// 		return
// 	}
// 	defer file.Close()

// 	// ✅ สร้าง Cloudinary instance
// 	cld, err := cloudinary.NewFromParams(
// 		"dvgxxafbb",                   // 👉 แทนด้วยชื่อ cloud ของคุณ
// 		"146741477549332",             // 👉 api key จาก dashboard
// 		"so_4ajw-nCCtJekaC7VAUAqySX4", // 👉 api secret จาก dashboard
// 	)

// 	if err != nil {
// 		http.Error(w, "Cloudinary init error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// ✅ อัปโหลดไฟล์ขึ้น Cloudinary
// 	ctx := context.Background()
// 	uploadResult, err := cld.Upload.Upload(ctx, file, uploader.UploadParams{
// 		Folder:   "users", // สร้างโฟลเดอร์ใน Cloudinary ชื่อ users
// 		PublicID: header.Filename,
// 	})
// 	if err != nil {
// 		http.Error(w, "Upload error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// ✅ ส่ง URL กลับไปให้ Angular
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]string{
// 		"path": uploadResult.SecureURL, // ✅ URL รูปจาก Cloudinary
// 	})
// }

// // ✅ handler สำหรับอัปเดตข้อมูลผู้ใช้

// func updateUser(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPut {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// ✅ รองรับทั้ง profileImage และ image จาก Angular
// 	var u struct {
// 		UID          int    `json:"uid"`
// 		Username     string `json:"username"`
// 		Email        string `json:"email"`
// 		ProfileImage string `json:"profileImage"`
// 		Image        string `json:"image"`
// 	}

// 	// ✅ แปลง JSON ที่รับมาจาก Angular
// 	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// ✅ กำหนดรูปที่จะอัปเดต (ถ้า profileImage ว่างแต่ image มี → ใช้ image)
// 	imageToUpdate := u.ProfileImage
// 	if imageToUpdate == "" && u.Image != "" {
// 		imageToUpdate = u.Image
// 	}

// 	// ✅ Debug log ฝั่ง backend (ดูได้จาก terminal)
// 	fmt.Printf("📩 อัปเดตผู้ใช้ UID=%d | image=%s\n", u.UID, imageToUpdate)

// 	// ✅ อัปเดตในฐานข้อมูล
// 	stmt, err := db.Prepare("UPDATE user SET username=?, email=?, image=? WHERE uid=?")
// 	if err != nil {
// 		http.Error(w, "Database prepare error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer stmt.Close()

// 	_, err = stmt.Exec(u.Username, u.Email, imageToUpdate, u.UID)
// 	if err != nil {
// 		http.Error(w, "Database exec error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// ✅ ดึงข้อมูลล่าสุดกลับมา
// 	var updatedUser User
// 	err = db.QueryRow(`
// 		SELECT uid, username, email, IFNULL(image,''), role, created_at
// 		FROM user
// 		WHERE uid = ?`, u.UID).Scan(
// 		&updatedUser.UID,
// 		&updatedUser.Username,
// 		&updatedUser.Email,
// 		&updatedUser.Image,
// 		&updatedUser.Role,
// 		&updatedUser.Created,
// 	)
// 	if err != nil {
// 		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// ✅ ส่งข้อมูลใหม่กลับให้ Angular
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"uid":          updatedUser.UID,
// 		"username":     updatedUser.Username,
// 		"email":        updatedUser.Email,
// 		"profileImage": updatedUser.Image, // คืนชื่อฟิลด์แบบเดียวกับ Angular
// 		"role":         updatedUser.Role,
// 		"createdAt":    updatedUser.Created,
// 	})
// }

// // ✅ handler เติมเงิน
// func topUpWallet(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req struct {
// 		UID    int     `json:"uid"`
// 		Amount float64 `json:"amount"`
// 	}
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request", http.StatusBadRequest)
// 		return
// 	}

// 	if req.Amount <= 0 {
// 		http.Error(w, "Invalid top-up amount", http.StatusBadRequest)
// 		return
// 	}

// 	tx, err := db.Begin()
// 	if err != nil {
// 		http.Error(w, "Transaction error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// ✅ ตรวจสอบว่าผู้ใช้มี wallet หรือยัง
// 	var walletID int
// 	err = tx.QueryRow("SELECT wallet_id FROM wallet WHERE uid = ?", req.UID).Scan(&walletID)
// 	if err == sql.ErrNoRows {
// 		// ถ้ายังไม่มี → สร้างใหม่
// 		res, err := tx.Exec("INSERT INTO wallet (uid, balance) VALUES (?, ?)", req.UID, req.Amount)
// 		if err != nil {
// 			tx.Rollback()
// 			http.Error(w, "Cannot create wallet: "+err.Error(), http.StatusInternalServerError)
// 			return
// 		}
// 		lastID, _ := res.LastInsertId()
// 		walletID = int(lastID)
// 	} else if err != nil {
// 		tx.Rollback()
// 		http.Error(w, "Query wallet error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	} else {
// 		// มีอยู่แล้ว → อัปเดตยอด
// 		_, err = tx.Exec("UPDATE wallet SET balance = balance + ? WHERE wallet_id = ?", req.Amount, walletID)
// 		if err != nil {
// 			tx.Rollback()
// 			http.Error(w, "Update wallet error: "+err.Error(), http.StatusInternalServerError)
// 			return
// 		}
// 	}

// 	// ✅ บันทึกประวัติใน wallet_transaction
// 	_, err = tx.Exec(`
// 		INSERT INTO wallet_transaction (wallet_id, amount, trans_type, description)
// 		VALUES (?, ?, 'topup', ?)`,
// 		walletID, req.Amount, fmt.Sprintf("Top up %.2f THB", req.Amount))
// 	if err != nil {
// 		tx.Rollback()
// 		http.Error(w, "Insert transaction error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	tx.Commit()

// 	// ✅ ดึงยอดคงเหลือล่าสุด
// 	var balance float64
// 	db.QueryRow("SELECT balance FROM wallet WHERE wallet_id = ?", walletID).Scan(&balance)

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"message": "Top-up successful",
// 		"uid":     req.UID,
// 		"balance": balance,
// 	})
// }

// // ✅ handler สำหรับแอดมิน ดูประวัติการเติมเงินทั้งหมด
// func getWalletTransactions(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodGet {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	rows, err := db.Query(`
// 		SELECT wt.trans_id, wt.wallet_id, wt.amount, wt.trans_type, wt.description, wt.created_at, u.username
// 		FROM wallet_transaction wt
// 		JOIN wallet w ON wt.wallet_id = w.wallet_id
// 		JOIN user u ON w.uid = u.uid
// 		ORDER BY wt.created_at DESC`)
// 	if err != nil {
// 		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer rows.Close()

// 	var transactions []WalletTransaction
// 	for rows.Next() {
// 		var t WalletTransaction
// 		if err := rows.Scan(&t.TransID, &t.WalletID, &t.Amount, &t.TransType, &t.Description, &t.CreatedAt, &t.Username); err != nil {
// 			http.Error(w, "Scan error: "+err.Error(), http.StatusInternalServerError)
// 			return
// 		}
// 		transactions = append(transactions, t)
// 	}

//		w.Header().Set("Content-Type", "application/json")
//		json.NewEncoder(w).Encode(transactions)
//	}
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

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// --- Structs for Database Models ---

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

var db *sql.DB

func main() {
	// --- Database Connection ---
	dsn := "66011212012:JittraladaDB2012@tcp(202.28.34.210:3309)/db66011212012"
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Cannot connect to database:", err)
	}
	defer db.Close()
	if err = db.Ping(); err != nil {
		log.Fatal("Cannot ping database:", err)
	}
	fmt.Println("✅ Connected to database successfully")

	// --- Router & Endpoints ---
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "CSShop Backend-API is running successfully!")
	})

	// User & Wallet Routes
	mux.HandleFunc("/user", getUsers)
	mux.HandleFunc("/register", registerUser)
	mux.HandleFunc("/login", loginUser)
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/update-profile", updateUser)

	// Game Management Routes
	mux.HandleFunc("/game-types", getGameTypes)
	mux.HandleFunc("/games", getGames)
	mux.HandleFunc("/game/add", addGame)
	mux.HandleFunc("/game/update", updateGame)
	mux.HandleFunc("/game/delete", deleteGame)

	// --- Server Startup ---
	handler := enableCORS(mux)
	ip := getLocalIP()
	url := fmt.Sprintf("http://%s:8080", ip)
	openBrowser(url) // Optional: remove this line if you don't want the browser to open automatically
	fmt.Printf("🚀 Server started at %s\n", url)
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", handler))
}

// --- Middleware & Helpers ---

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip := ipnet.IP.To4(); ip != nil {
				if ip[0] == 192 || ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
					return ip.String()
				}
			}
		}
	}
	return "localhost"
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
		args = []string{url}
	}
	exec.Command(cmd, args...).Start()
}

// --- User Management Handlers ---

func getUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT uid, username, email, IFNULL(image, ''), role, created_at FROM user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.UID, &u.Username, &u.Email, &u.Image, &u.Role, &u.Created); err != nil {
			http.Error(w, "Scan error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var u struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Image    string `json:"image"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check for duplicate email
	var exists int
	err := db.QueryRow("SELECT COUNT(*) FROM user WHERE email = ?", u.Email).Scan(&exists)
	if err != nil {
		http.Error(w, "Database query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		http.Error(w, "Email already exists", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Insert into database
	stmt, err := db.Prepare("INSERT INTO user (username, email, password, image, role, created_at) VALUES (?, ?, ?, ?, ?, NOW())")
	if err != nil {
		http.Error(w, "Database prepare error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(u.Username, u.Email, string(hashedPassword), u.Image, u.Role)
	if err != nil {
		http.Error(w, "Database exec error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	lastID, _ := res.LastInsertId()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"uid":     lastID,
	})
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var user User
	var hashedPassword string
	err := db.QueryRow("SELECT uid, username, password, role, IFNULL(image,''), created_at FROM user WHERE email = ?",
		input.Email).Scan(&user.UID, &user.Username, &hashedPassword, &user.Role, &user.Image, &user.Created)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Email not found", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Database query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Compare password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(input.Password))
	if err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Login successful",
		"uid":       user.UID,
		"username":  user.Username,
		"email":     input.Email,
		"role":      user.Role,
		"image":     user.Image,
		"createdAt": user.Created,
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Could not get file from form", http.StatusBadRequest)
		return
	}
	defer file.Close()

	cld, err := cloudinary.NewFromParams("dvgxxafbb", "146741477549332", "so_4ajw-nCCtJekaC7VAUAqySX4")
	if err != nil {
		http.Error(w, "Cloudinary init error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ctx := context.Background()
	uploadResult, err := cld.Upload.Upload(ctx, file, uploader.UploadParams{
		Folder:   "users",
		PublicID: header.Filename,
	})
	if err != nil {
		http.Error(w, "Upload error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"path": uploadResult.SecureURL,
	})
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var u struct {
		UID      int    `json:"uid"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Image    string `json:"image"`
	}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare("UPDATE user SET username=?, email=?, image=? WHERE uid=?")
	if err != nil {
		http.Error(w, "Database prepare error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(u.Username, u.Email, u.Image, u.UID)
	if err != nil {
		http.Error(w, "Database exec error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User updated successfully",
	})
}

// --- Game Management Handlers ---

func getGameTypes(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT type_id, type_name FROM game_type ORDER BY type_name")
	if err != nil {
		http.Error(w, "Database query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var gameTypes []GameType
	for rows.Next() {
		var gt GameType
		if err := rows.Scan(&gt.TypeID, &gt.TypeName); err != nil {
			http.Error(w, "Database scan error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		gameTypes = append(gameTypes, gt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gameTypes)
}

func getGames(w http.ResponseWriter, r *http.Request) {
	query := `
        SELECT
            g.game_id, g.name, IFNULL(g.description, ''),
            IFNULL(DATE_FORMAT(g.release_date, '%Y-%m-%d'), ''),
            g.sales, g.price, IFNULL(g.image, ''), g.type_id, IFNULL(gt.type_name, 'N/A')
        FROM game g
        LEFT JOIN game_type gt ON g.type_id = gt.type_id
        ORDER BY g.game_id DESC`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Database query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var games []Game
	for rows.Next() {
		var g Game
		err := rows.Scan(&g.GameID, &g.Name, &g.Description, &g.ReleaseDate, &g.Sales, &g.Price, &g.Image, &g.TypeID, &g.TypeName)
		if err != nil {
			http.Error(w, "Database scan error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		games = append(games, g)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(games)
}

func addGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var g Game
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var releaseDate interface{} = g.ReleaseDate
	if g.ReleaseDate == "" {
		releaseDate = nil
	}

	stmt, err := db.Prepare(`INSERT INTO game (name, description, release_date, price, image, type_id) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		http.Error(w, "Database prepare error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(g.Name, g.Description, releaseDate, g.Price, g.Image, g.TypeID)
	if err != nil {
		http.Error(w, "Database exec error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	lastID, _ := res.LastInsertId()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "Game added successfully", "game_id": lastID})
}

func updateGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var g Game
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if g.GameID == 0 {
		http.Error(w, "Game ID is required", http.StatusBadRequest)
		return
	}

	var releaseDate interface{} = g.ReleaseDate
	if g.ReleaseDate == "" {
		releaseDate = nil
	}

	stmt, err := db.Prepare(`UPDATE game SET name = ?, description = ?, release_date = ?, price = ?, image = ?, type_id = ? WHERE game_id = ?`)
	if err != nil {
		http.Error(w, "Database prepare error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(g.Name, g.Description, releaseDate, g.Price, g.Image, g.TypeID, g.GameID)
	if err != nil {
		http.Error(w, "Database exec error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Game updated successfully"})
}

func deleteGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		GameID int `json:"game_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.GameID == 0 {
		http.Error(w, "Game ID is required", http.StatusBadRequest)
		return
	}

	stmt, err := db.Prepare("DELETE FROM game WHERE game_id = ?")
	if err != nil {
		http.Error(w, "Database prepare error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(req.GameID)
	if err != nil {
		http.Error(w, "Database exec error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Game deleted successfully"})
}
