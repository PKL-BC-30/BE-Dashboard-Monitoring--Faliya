use actix_cors::Cors;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use bcrypt::{hash, verify, DEFAULT_COST};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rand::distributions::Uniform;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, Error, NoTls};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct GetUser {
    id: Option<i32>,
    name: String,
    birthdate: String,
    blood_type: String,
    gender: String,
    age: i32,
    job: String,
    email: String,
    income: Option<String>,
    password: Option<String>,
    province: String,
    regency: String,
    district: String,
}

#[derive(Serialize, Deserialize)]
struct InsertUser {
    name: String,
    birthdate: String,
    blood_type: String,
    gender: String,
    age: i32,
    job: String,
    email: String,
    password: String,
    security_question: String,
    security_answer: String,
    income: Option<String>,
    province: String,
    regency: String,
    district: String,
}

#[derive(Deserialize)]
struct PatchUser {
    name: Option<String>,
    birthdate: Option<String>,
    blood_type: Option<String>,
    gender: Option<String>,
    age: Option<i32>,
    job: Option<String>,
    email: Option<String>,
    password: Option<String>,
    security_question: Option<String>,
    security_answer: Option<String>,
    income: Option<String>,
    province: Option<String>,
    regency: Option<String>,
    district: Option<String>,
}

#[derive(Deserialize)]
struct UpdateUser {
    name: Option<String>,
    birthdate: Option<String>,
    blood_type: Option<String>,
    gender: Option<String>,
    age: Option<i32>,
    job: Option<String>,
    income: Option<String>,
    province: Option<String>,
    regency: Option<String>,
    district: Option<String>,
}

#[derive(Deserialize)]
struct VerifyOtp {
    email: String,
    otp: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user_id: i32,
    user_name: String,
}

#[derive(Deserialize)]
struct ForgotPasswordRequest {
    email: String,
    security_question: String,
    security_answer: String,
    password: String,
}

#[derive(Serialize)]
struct BloodTypeStats {
    blood_type: String,
    jumlah: i64,
}

#[derive(Serialize)]
struct AgeGroupStats {
    age_group: String,
    count: i64,
}

#[derive(Serialize)]
struct GenderDistribution {
    gender: String,
    count: i64,
}

#[derive(Serialize)]
struct IncomeStats {
    income: Option<String>,
    count: i64,
}

// Struktur untuk permintaan email
#[derive(Deserialize)]
struct OtpRequest {
    otp: String,
}

async fn get_email_by_otp(otp_request: web::Json<OtpRequest>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let result = client
        .query_one(
            "SELECT email FROM users WHERE otp = $1",
            &[&otp_request.otp],
        )
        .await;

    match result {
        Ok(row) => {
            let email: String = row.get(0);
            HttpResponse::Ok().json(email)
        }
        Err(e) => {
            eprintln!("Error retrieving email: {}", e);
            HttpResponse::InternalServerError().json("Error retrieving email")
        }
    }
}

async fn connect_to_db() -> Result<Client, Error> {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=#Adharafaliya01_ dbname=postgres",
        NoTls,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    Ok(client)
}

async fn send_email(email: &str, otp: &str) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from(Mailbox::new(None, "adharafaliyautanti@gmail.com".parse()?))
        .to(Mailbox::new(None, email.parse()?))
        .subject("Registration OTP")
        .body(format!("Your OTP code is: {}", otp))
        .unwrap();

    let creds = Credentials::new(
        "adharafaliyautanti@gmail.com".to_string(),
        "knfpggyxmslseiog".to_string(),
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}

async fn get_users() -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let rows = match client
        .query("SELECT id, name, birthdate, blood_type, gender, age, job, email, income, password, province, regency, district FROM users WHERE is_verified = true", &[])
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("Failed to query users: {}", e);
            return HttpResponse::InternalServerError().json("Failed to query users");
        }
    };

    let users: Vec<GetUser> = rows
        .iter()
        .map(|row| GetUser {
            id: Some(row.get(0)),
            name: row.get(1),
            birthdate: row.get(2),
            blood_type: row.get(3),
            gender: row.get(4),
            age: row.get(5),
            job: row.get(6),
            email: row.get(7),
            income: row.get(8),
            password: row.get(9),
            province: row.get(10),
            regency: row.get(11),
            district: row.get(12),
        })
        .collect();

    HttpResponse::Ok().json(users)
}

async fn insert_user(new_user: web::Json<InsertUser>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let email_check_result = client
        .query_one(
            "SELECT COUNT(*) FROM users WHERE email = $1",
            &[&new_user.email],
        )
        .await;

    match email_check_result {
        Ok(row) => {
            let email_count: i64 = row.get(0);
            if email_count > 0 {
                return HttpResponse::BadRequest().json("Email sudah terdaftar.");
            }
        }
        Err(e) => {
            eprintln!("Gagal memeriksa email: {}", e);
            return HttpResponse::InternalServerError().json("Gagal memeriksa email.");
        }
    }

    let hashed_password = match hash(&new_user.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to hash password: {}", e);
            return HttpResponse::InternalServerError().json("Error hashing password");
        }
    };

    // Generate a random numeric OTP code
    let mut rng = thread_rng();
    let uniform = Uniform::from(0..10);
    let otp: String = (0..6).map(|_| rng.sample(&uniform).to_string()).collect(); // Panjang OTP 6 angka

    let result = client
        .execute(
            "INSERT INTO users (name, birthdate, blood_type, gender, age, job, email, password, otp, security_question, security_answer, income, province, regency, district) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",           
             &[
                &new_user.name,
                &new_user.birthdate,
                &new_user.blood_type,
                &new_user.gender,
                &new_user.age,
                &new_user.job,
                &new_user.email,
                &hashed_password,
                &otp,
                &new_user.security_question,
                &new_user.security_answer,
                &new_user.income,
                &new_user.province,
                &new_user.regency,
                &new_user.district,
            ],
        )
        .await;

    match result {
        Ok(_) => {
            if let Err(e) = send_email(&new_user.email, &otp).await {
                eprintln!("Failed to send email: {}", e);
            }
            HttpResponse::Ok().json("User added successfully and OTP sent")
        }
        Err(e) => {
            eprintln!("Error inserting user: {}", e);
            HttpResponse::InternalServerError().json("Error adding user")
        }
    }
}

async fn update_user(user: web::Json<UpdateUser>, id: web::Path<i32>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let result = client
        .execute(
            "UPDATE users SET 
                name = COALESCE($1, name), 
                birthdate = COALESCE($2, birthdate), 
                blood_type = COALESCE($3, blood_type), 
                gender = COALESCE($4, gender), 
                age = COALESCE($5, age), 
                job = COALESCE($6, job), 
                income = COALESCE($7, income), 
                province = COALESCE($8, province), 
                regency = COALESCE($9, regency), 
                district = COALESCE($10, district) 
             WHERE id = $11",
            &[
                &user.name,
                &user.birthdate,
                &user.blood_type,
                &user.gender,
                &user.age,
                &user.job,
                &user.income,
                &user.province,
                &user.regency,
                &user.district,
                &id.into_inner(),
            ],
        )
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().json("User updated successfully"),
        Err(e) => {
            eprintln!("Error updating user: {}", e);
            HttpResponse::InternalServerError().json("Error updating user")
        }
    }
}

async fn forgot_password(req: web::Json<ForgotPasswordRequest>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    // Hash the new password
    let hashed_password = match hash(&req.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to hash password: {}", e);
            return HttpResponse::InternalServerError().json("Error hashing password");
        }
    };

    // Update password in the database using email, security question, and security answer
    let result = client
        .execute(
            "UPDATE users SET password = $1 WHERE email = $2 AND security_answer = $3 AND security_question = $4",
            &[&hashed_password, &req.email, &req.security_answer, &req.security_question],
        )
        .await;

    match result {
        Ok(rows_affected) if rows_affected > 0 => {
            HttpResponse::Ok().json("Password updated successfully")
        }
        Ok(_) => HttpResponse::NotFound().json("User or security question not found"),
        Err(e) => {
            eprintln!("Error updating password: {}", e);
            HttpResponse::InternalServerError().json("Error updating password")
        }
    }
}

async fn patch_user(id: web::Path<i32>, user: web::Json<PatchUser>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let result = client
        .execute(
            "UPDATE users SET 
                name = COALESCE($1, name), 
                birthdate = COALESCE($2, birthdate), 
                blood_type = COALESCE($3, blood_type), 
                gender = COALESCE($4, gender), 
                age = COALESCE($5, age), 
                job = COALESCE($6, job), 
                email = COALESCE($7, email), 
                password = COALESCE($8, password), 
                security_question = COALESCE($9, security_question), 
                income = COALESCE($10, income), 
                security_answer = COALESCE($11, security_answer), 
                province = COALESCE($12, province), 
                regency = COALESCE($13, regency), 
                district = COALESCE($14, district)
            WHERE id = $15",
            &[
                &user.name,
                &user.birthdate,
                &user.blood_type,
                &user.gender,
                &user.age,
                &user.job,
                &user.email,
                &user.password,
                &user.security_question,
                &user.income,
                &user.security_answer,
                &user.province, // Menambahkan province
                &user.regency,  // Menambahkan regency
                &user.district, // Menambahkan district
                &id.into_inner(),
            ],
        )
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().json("User updated successfully"),
        Err(e) => {
            eprintln!("Error updating user: {}", e);
            HttpResponse::InternalServerError().json("Error updating user")
        }
    }
}

async fn delete_user(id: web::Path<i32>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let id = id.into_inner();

    let result = client
        .execute("DELETE FROM users WHERE id = $1", &[&id])
        .await;

    match result {
        Ok(_) => {
            let otp = "Your account has been deleted."; // Adjust according to the context
            if let Err(e) = send_email("skyp00ding@gmail.com", otp).await {
                // Replace with appropriate email
                eprintln!("Failed to send email: {}", e);
            }
            HttpResponse::Ok().json("User deleted successfully")
        }
        Err(e) => {
            eprintln!("Error deleting user: {}", e);
            HttpResponse::InternalServerError().json("Error deleting user")
        }
    }
}

async fn verify_otp(verification: web::Json<VerifyOtp>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let result = client
        .execute(
            "UPDATE users SET is_verified = true WHERE email = $1 AND otp = $2",
            &[&verification.email, &verification.otp],
        )
        .await;

    match result {
        Ok(updated_rows) if updated_rows > 0 => {
            HttpResponse::Ok().json("OTP verified successfully, you can now login.")
        }
        Ok(_) => HttpResponse::NotFound().json("Invalid email or OTP"),
        Err(e) => {
            eprintln!("Error verifying OTP: {}", e);
            HttpResponse::InternalServerError().json("Error verifying OTP")
        }
    }
}

async fn login_user(login_info: web::Json<LoginRequest>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    println!("Attempting to log in user with email: {}", login_info.email);

    let result = client
        .query_one(
            "SELECT id, password, name FROM users WHERE email = $1 AND is_verified = true",
            &[&login_info.email],
        )
        .await;

    let row = match result {
        Ok(row) => row,
        Err(_) => {
            eprintln!(
                "User not found or not verified for email: {}",
                login_info.email
            );
            return HttpResponse::Unauthorized()
                .json("Invalid email or password, or account not verified");
        }
    };

    let id: i32 = row.get(0);
    let hashed_password: String = row.get(1);
    let user_name: String = row.get(2);

    println!("User found with ID: {}. Verifying password...", id);

    if verify(&login_info.password, &hashed_password).unwrap_or(false) {
        let token = Uuid::new_v4().to_string();

        let result = client
            .execute("UPDATE users SET token = $1 WHERE id = $2", &[&token, &id])
            .await;

        let update_status = client
            .execute("UPDATE users SET status = 'online' WHERE id = $1", &[&id])
            .await;

        if result.is_ok() && update_status.is_ok() {
            println!("Login successful, token generated for user ID: {}", id);

            let login_response = LoginResponse {
                token,
                user_id: id,
                user_name,
            };

            HttpResponse::Ok().json(login_response)
        } else {
            eprintln!("Error updating token or status for user ID: {}", id);
            HttpResponse::InternalServerError().json("Error during login")
        }
    } else {
        eprintln!("Password verification failed for user ID: {}", id);
        HttpResponse::Unauthorized().json("Invalid email or password")
    }
}

// CARD TOTAL PENGGUNA
async fn get_total_users() -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let row = match client
        .query_one("SELECT COUNT(*) FROM users WHERE is_verified = true", &[])
        .await
    {
        Ok(row) => row,
        Err(e) => {
            eprintln!("Failed to count users: {}", e);
            return HttpResponse::InternalServerError().json("Failed to count users");
        }
    };

    let total_users: i64 = row.get(0);
    HttpResponse::Ok().json(total_users)
}

async fn get_blood_type_stats() -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let rows = match client
        .query(
            "SELECT blood_type, COUNT(*) FROM users WHERE is_verified = true GROUP BY blood_type",
            &[],
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("Failed to query blood type stats: {}", e);
            return HttpResponse::InternalServerError().json("Failed to query blood type stats");
        }
    };

    let stats: Vec<BloodTypeStats> = rows
        .iter()
        .map(|row| BloodTypeStats {
            blood_type: row.get(0),
            jumlah: row.get(1), // Menggunakan jumlah
        })
        .collect();

    HttpResponse::Ok().json(stats)
}

async fn get_age_group_stats() -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let rows = match client
        .query(
            "SELECT CASE
                    WHEN age BETWEEN 0 AND 9 THEN '0-9'
                    WHEN age BETWEEN 10 AND 19 THEN '10-19'
                    WHEN age BETWEEN 20 AND 29 THEN '20-29'
                    WHEN age BETWEEN 30 AND 39 THEN '30-39'
                    WHEN age BETWEEN 40 AND 49 THEN '40-49'
                    ELSE '50+'
                  END AS age_group,
                  COUNT(*)
             FROM users
             WHERE is_verified = true
             GROUP BY age_group",
            &[],
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("Failed to query age group stats: {}", e);
            return HttpResponse::InternalServerError().json("Failed to query age group stats");
        }
    };

    let stats: Vec<AgeGroupStats> = rows
        .iter()
        .map(|row| AgeGroupStats {
            age_group: row.get(0),
            count: row.get(1),
        })
        .collect();

    HttpResponse::Ok().json(stats)
}

async fn get_gender_distribution() -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let rows = match client
        .query(
            "SELECT gender, COUNT(*) FROM users WHERE is_verified = true GROUP BY gender",
            &[],
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("Failed to query gender distribution: {}", e);
            return HttpResponse::InternalServerError().json("Failed to query gender distribution");
        }
    };

    let stats: Vec<GenderDistribution> = rows
        .iter()
        .map(|row| {
            let gender: String = row.get(0);
            let count: i64 = row.get(1);

            GenderDistribution { gender, count }
        })
        .collect();

    HttpResponse::Ok().json(stats)
}

async fn get_students_count() -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let row = match client
        .query_one(
            "SELECT COUNT(*) FROM users WHERE job = 'Murid' AND is_verified = true",
            &[],
        )
        .await
    {
        Ok(row) => row,
        Err(e) => {
            eprintln!("Failed to query students count: {}", e);
            return HttpResponse::InternalServerError().json("Failed to query students count");
        }
    };

    let count: i64 = row.get(0);
    HttpResponse::Ok().json(count)
}

// Fungsi untuk mengambil jumlah Pekerja
async fn get_workers_count() -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let row = match client
        .query_one(
            "SELECT COUNT(*) FROM users WHERE job = 'Pekerja' AND is_verified = true",
            &[],
        )
        .await
    {
        Ok(row) => row,
        Err(e) => {
            eprintln!("Failed to query workers count: {}", e);
            return HttpResponse::InternalServerError().json("Failed to query workers count");
        }
    };

    let count: i64 = row.get(0);
    HttpResponse::Ok().json(count)
}

async fn get_income_stats() -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let rows = match client
        .query(
            "SELECT income, COUNT(*) FROM users WHERE income IS NOT NULL GROUP BY income ORDER BY income",
            &[],
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("Failed to query income stats: {}", e);
            return HttpResponse::InternalServerError().json("Failed to query income stats");
        }
    };

    let income_stats: Vec<IncomeStats> = rows
        .iter()
        .map(|row| IncomeStats {
            income: row.get(0),
            count: row.get(1),
        })
        .collect();

    HttpResponse::Ok().json(income_stats)
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: i32,
    name: String,
    birthdate: String,
    blood_type: String,
    gender: String,
    age: i32,
    job: String,
    income: Option<String>,
}

async fn get_user_by_id(id: web::Path<i32>) -> impl Responder {
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    let row = client
        .query_one("SELECT id, name, birthdate, blood_type, gender, age, job, income FROM users WHERE id = $1", &[&id.into_inner()])
        .await;

    match row {
        Ok(row) => {
            let user = User {
                id: row.get("id"),
                name: row.get("name"),
                birthdate: row.get("birthdate"),
                blood_type: row.get::<_, String>("blood_type").trim().to_string(),
                gender: row.get("gender"),
                age: row.get("age"),
                job: row.get("job"),
                income: row.get("income"),
            };
            HttpResponse::Ok().json(user)
        }
        Err(e) => {
            eprintln!("Error retrieving user: {}", e);
            HttpResponse::NotFound().json("User not found")
        }
    }
}

async fn logout(req: HttpRequest) -> impl Responder {
    // Ambil token dari header Authorization
    let token = match req.headers().get("Authorization") {
        Some(header_value) => match header_value.to_str() {
            Ok(token) => token,
            Err(_) => return HttpResponse::BadRequest().json("Invalid token format"),
        },
        None => return HttpResponse::Unauthorized().json("No token provided"),
    };

    let token = token.trim_start_matches("Bearer "); // Hilangkan prefix "Bearer " jika ada

    // Koneksi ke database
    let client = match connect_to_db().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            return HttpResponse::InternalServerError().json("Failed to connect to database");
        }
    };

    // Hapus token dari database
    let result = client
        .execute(
            "UPDATE users SET token = NULL, status = 'offline' WHERE token = $1",
            &[&token],
        )
        .await;

    match result {
        Ok(rows_affected) => {
            if rows_affected > 0 {
                HttpResponse::Ok().json("Logout successful")
            } else {
                HttpResponse::Unauthorized().json("Invalid token")
            }
        }
        Err(e) => {
            eprintln!("Error during logout: {}", e);
            HttpResponse::InternalServerError().json("Error during logout")
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ProvinceGenderData {
    gender: String,
    count: i64,
}

// Fungsi ini akan digunakan untuk menghandle endpoint
async fn gender_data_by_province(path: web::Path<String>) -> impl Responder {
    let province = path.into_inner();  // Mengambil nama provinsi dari path
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=#Adharafaliya01_ dbname=postgres",
        NoTls,
    )
    .await
    .unwrap();

    // The connection must be polled to operate
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let gender_counts = vec![
        (
            "male",
            format!(
                "SELECT COUNT(*) FROM users WHERE province = '{}' AND gender = 'male'",
                province
            ),
        ),
        (
            "female",
            format!(
                "SELECT COUNT(*) FROM users WHERE province = '{}' AND gender = 'female'",
                province
            ),
        ),
    ];

    let mut results = Vec::new();

    for (gender, query) in gender_counts {
        let count: i64 = client.query_one(&query, &[]).await.unwrap().get(0);
        results.push(ProvinceGenderData {
            gender: gender.to_string(),
            count,
        });
    }

    HttpResponse::Ok().json(results)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(Cors::permissive())
            .route("/users/email-by-otp", web::post().to(get_email_by_otp))
            .route("/users/register", web::post().to(insert_user))
            .route("/users/login", web::post().to(login_user))
            .route("/users/forgot_password", web::post().to(forgot_password))
            .route("/users/verified", web::post().to(verify_otp))
            .route("/users/delete/{id}", web::delete().to(delete_user))
            .route("/users/data", web::get().to(get_users))
            .route("/users/edit/{id}", web::put().to(update_user))
            .route("/users/edit/{id}", web::get().to(get_user_by_id))
            .route("/users/{id}", web::patch().to(patch_user))
            .route("/users/total_pengguna", web::get().to(get_total_users))
            .route(
                "/users/blood_type_stats",
                web::get().to(get_blood_type_stats),
            )
            .route("/users/age", web::get().to(get_age_group_stats))
            .route("/users/gender", web::get().to(get_gender_distribution))
            .route("/users/students_count", web::get().to(get_students_count))
            .route("/users/workers_count", web::get().to(get_workers_count))
            .route("/users/income-stats", web::get().to(get_income_stats))
            .route("/gender-data/{province}", web::get().to(gender_data_by_province))
            .route("/logout", web::post().to(logout))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
