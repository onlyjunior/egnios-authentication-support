package com.egnios.authentication.service;

import com.egnios.authentication.config.auth.firebase.FirebaseTokenHolder;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;

import java.util.Optional;

public interface IFirebaseService {

    Optional<UserRecord> findByEmailName(String uid);

    FirebaseTokenHolder parseToken(String idToken) throws FirebaseAuthException;

    String createUser(String email, String password) throws FirebaseAuthException;

    void deleteUser(String uid) throws FirebaseAuthException;

    void enableUser(String uid) throws FirebaseAuthException;

    void disableUser(String uid) throws FirebaseAuthException;

    void updatePassword(String uid, String password) throws FirebaseAuthException;

    void updateDisplayName(String uid, String firstname, String lastname) throws FirebaseAuthException;
}
