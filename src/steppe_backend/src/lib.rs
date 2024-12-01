use candid::{CandidType, Principal};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl,
    StableBTreeMap,
    Storable,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

// Implement Storable trait for User to work with stable structures
impl Storable for User {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }

    const BOUND: ic_stable_structures::storable::Bound = ic_stable_structures::storable::Bound::Unbounded;
}

// User structure to store detailed information
#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: Principal,
    pub username: String,
    pub email: Option<String>,
    pub profile_image: Option<String>,
    pub is_admin: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

// User Management Module
pub struct UserManagement {
    users: StableBTreeMap<Principal, User, VirtualMemory<DefaultMemoryImpl>>,
}

impl UserManagement {
    // Constructor
    pub fn new(memory_manager: &MemoryManager<DefaultMemoryImpl>) -> Self {
        Self {
            users: StableBTreeMap::new(
                memory_manager.get(MemoryId::new(1))
            ),
        }
    }

    // Authenticate user and create/update profile
    pub fn authenticate_user(
        &mut self, 
        principal: Principal, 
        username: String, 
        email: Option<String>, 
        profile_image: Option<String>
    ) -> Result<User, String> {
        // Validate input
        if username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }

        // Check if user already exists
        let timestamp = ic_cdk::api::time();
        let user = match self.users.get(&principal) {
            Some(existing_user) => {
                // Update existing user
                let updated_user = User {
                    id: principal,
                    username: username.clone(),
                    email: email.or(existing_user.email.clone()),
                    profile_image: profile_image.or(existing_user.profile_image.clone()),
                    is_admin: existing_user.is_admin,
                    created_at: existing_user.created_at,
                    updated_at: timestamp,
                };
                self.users.insert(principal, updated_user.clone());
                updated_user
            },
            None => {
                // Create new user
                let new_user = User {
                    id: principal,
                    username,
                    email,
                    profile_image,
                    is_admin: false,
                    created_at: timestamp,
                    updated_at: timestamp,
                };
                self.users.insert(principal, new_user.clone());
                new_user
            }
        };

        Ok(user)
    }

    // Get user by principal
    pub fn get_user(&self, principal: &Principal) -> Option<User> {
        self.users.get(principal)
    }

    // Update user profile
    pub fn update_user_profile(
        &mut self, 
        principal: Principal, 
        username: Option<String>, 
        email: Option<String>, 
        profile_image: Option<String>
    ) -> Result<User, String> {
        // Ensure user exists
        let user = self.users.get(&principal)
            .ok_or_else(|| "User not found".to_string())?;

        // Update fields if provided
        let updated_user = User {
            id: principal,
            username: username.unwrap_or(user.username),
            email: email.or(user.email),
            profile_image: profile_image.or(user.profile_image),
            is_admin: user.is_admin,
            created_at: user.created_at,
            updated_at: ic_cdk::api::time(),
        };

        // Update the user
        self.users.insert(principal, updated_user.clone());

        Ok(updated_user)
    }

    // Delete user profile
    pub fn delete_user(&mut self, principal: &Principal) -> Result<(), String> {
        if self.users.remove(principal).is_some() {
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }

    // Admin method to toggle admin status
    pub fn set_admin_status(
        &mut self, 
        requester: Principal, 
        target_user: Principal, 
        is_admin: bool
    ) -> Result<(), String> {
        // Verify requester is an admin
        let requester_user = self.users.get(&requester)
            .ok_or_else(|| "Requester not found".to_string())?;
        
        if !requester_user.is_admin {
            return Err("Only admins can change admin status".to_string());
        }

        // Get and modify target user
        let user = self.users.get(&target_user)
            .ok_or_else(|| "Target user not found".to_string())?;
        
        let updated_user = User {
            is_admin,
            ..user.clone()
        };

        // Update the user
        self.users.insert(target_user, updated_user);

        Ok(())
    }

    // List all users (admin only)
    pub fn list_users(&self, requester: &Principal) -> Result<Vec<User>, String> {
        // Verify requester is an admin
        let requester_user = self.users.get(requester)
            .ok_or_else(|| "Requester not found".to_string())?;
        
        if !requester_user.is_admin {
            return Err("Only admins can list users".to_string());
        }

        // Return all users
        Ok(self.users.iter().map(|(_, user)| user).collect())
    }
}

ic_cdk::export_candid!();