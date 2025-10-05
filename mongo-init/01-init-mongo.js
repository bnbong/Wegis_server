// --------------------------------------------------------------------------
// MongoDB initialization script
//
// @author bnbong bbbong9@gmail.com
// --------------------------------------------------------------------------

// Note: Root user is already created by Docker Compose's MONGO_INITDB_ROOT_USERNAME
// We just need to switch to the phishing_feedback database and set it up

// Switch to the phishing_feedback database for initialization
db = db.getSiblingDB('phishing_feedback');

// Create collections and indexes
db.createCollection('user_feedback');

// Create indexes for user_feedback collection
db.user_feedback.createIndex({ "url": 1 });
db.user_feedback.createIndex({ "feedback_time": -1 });
db.user_feedback.createIndex({ "user_id": 1 });
db.user_feedback.createIndex({ "is_phishing": 1 });

// Create a sample document to ensure collection structure
db.user_feedback.insertOne({
  _id: ObjectId(),
  url: "https://example.com",
  user_id: "system_init",
  feedback_time: new Date(),
  is_phishing: false,
  actual_result: false,
  confidence: 0.95,
  feedback_text: "System initialization document - can be removed",
  created_at: new Date(),
  updated_at: new Date()
});

print('MongoDB initialization completed for Wegis Server');
print('Database: phishing_feedback');
print('Collection: user_feedback with indexes created');
print('Root user authentication: use MONGO_INITDB_ROOT_USERNAME credentials with authSource=admin');
