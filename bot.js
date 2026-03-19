require("dotenv").config()
const { Client, LocalAuth } = require("whatsapp-web.js")
const qrcode = require("qrcode-terminal")
const express = require("express")
const crypto = require("crypto")
const { createClient } = require("@supabase/supabase-js")

// ---- Config ----
const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY
const PORT = process.env.PORT

// ---- Supabase ----
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

// ---- OTP Store (in memory) ----
// { "919876543210": { otp: "123456", expires: timestamp, verified: false } }
const otpStore = {}

// ---- Generate OTP ----
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString()
}

// ---- Format phone for WhatsApp ----
function formatPhone(phone) {
  // Remove + or spaces
  const cleaned = phone.replace(/\D/g, "")
  return `${cleaned}@c.us`
}

// ---- WhatsApp Client ----
const whatsapp = new Client({
  authStrategy: new LocalAuth(),
  puppeteer: {
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  }
})

whatsapp.on("qr", (qr) => {
  console.log("📱 Scan QR:")
  qrcode.generate(qr, { small: true })
})

whatsapp.on("ready", () => {
  console.log("✅ WhatsApp ready!")
})

whatsapp.on("disconnected", () => {
  whatsapp.initialize()
})

// ---- Express API ----
const app = express()
app.use(express.json())

// 1. REQUEST OTP
// POST /auth/send-otp
// Body: { phone: "919876543210" }
app.post("/auth/send-otp", async (req, res) => {
  try {
    const { phone } = req.body

    if (!phone) {
      return res.status(400).json({ error: "Phone number required" })
    }

    // Check if OTP was sent recently (60 second cooldown)
    const existing = otpStore[phone]
    if (existing && Date.now() < existing.expires - 240000) {
      return res.status(429).json({
        error: "Please wait 60 seconds before requesting again"
      })
    }

    // Generate OTP
    const otp = generateOTP()
    const expires = Date.now() + 5 * 60 * 1000 // 5 minutes

    // Store OTP
    otpStore[phone] = { otp, expires, verified: false }

    // Send via WhatsApp
    const waNumber = formatPhone(phone)
    await whatsapp.sendMessage(waNumber, 
      `🔐 *Your Verification Code*\n\n` +
      `*${otp}*\n\n` +
      `Valid for 5 minutes.\n` +
      `Do not share this with anyone.`
    )

    console.log(`✅ OTP sent to ${phone}: ${otp}`)

    res.json({
      success: true,
      message: "OTP sent via WhatsApp",
      expires_in: 300 // seconds
    })

  } catch (err) {
    console.error("Send OTP error:", err)
    res.status(500).json({ error: "Failed to send OTP" })
  }
})

// 2. VERIFY OTP + Create Supabase Session
// POST /auth/verify-otp
// Body: { phone: "919876543210", otp: "123456" }
app.post("/auth/verify-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body

    if (!phone || !otp) {
      return res.status(400).json({ error: "Phone and OTP required" })
    }

    const record = otpStore[phone]

    // Check if OTP exists
    if (!record) {
      return res.status(400).json({ error: "No OTP found. Request a new one." })
    }

    // Check expiry
    if (Date.now() > record.expires) {
      delete otpStore[phone]
      return res.status(400).json({ error: "OTP expired. Request a new one." })
    }

    // Check if already verified
    if (record.verified) {
      return res.status(400).json({ error: "OTP already used." })
    }

    // Verify OTP
    if (record.otp !== otp) {
      return res.status(400).json({ error: "Invalid OTP" })
    }

    // Mark as verified
    otpStore[phone].verified = true

    // Create or get user in Supabase
    const email = `${phone}@whatsapp.user` // dummy email for phone users

    // Check if user exists
    const { data: existingUsers } = await supabase
      .from("users")
      .select("*")
      .eq("phone", phone)
      .limit(1)

    let userId

    if (existingUsers && existingUsers.length > 0) {
      // Existing user
      userId = existingUsers[0].id
      console.log(`✅ Existing user logged in: ${phone}`)
    } else {
      // Create new user in Supabase Auth
      const { data: newUser, error: createError } = await supabase.auth.admin.createUser({
        email,
        password: crypto.randomBytes(32).toString("hex"), // random password
        email_confirm: true,
        user_metadata: { phone }
      })

      if (createError) throw createError

      // Save to users table
      await supabase.from("users").insert({
        id: newUser.user.id,
        phone,
        created_at: new Date().toISOString()
      })

      userId = newUser.user.id
      console.log(`✅ New user created: ${phone}`)
    }

    // Generate Supabase session
    const { data: session, error: sessionError } = await supabase.auth.admin.generateLink({
      type: "magiclink",
      email,
    })

    if (sessionError) throw sessionError

    // Clean up OTP
    delete otpStore[phone]

    res.json({
      success: true,
      message: "OTP verified successfully",
      user_id: userId,
      access_token: session.properties.hashed_token,
    })

  } catch (err) {
    console.error("Verify OTP error:", err)
    res.status(500).json({ error: "Verification failed" })
  }
})

// 3. CHECK STATUS
// GET /auth/status
app.get("/auth/status", (req, res) => {
  res.json({
    whatsapp: whatsapp.info ? "connected" : "disconnected",
    status: "running"
  })
})

// ---- Start Everything ----
whatsapp.initialize()

app.listen(PORT, () => {
  console.log(`🚀 Auth server running on port ${PORT}`)
})