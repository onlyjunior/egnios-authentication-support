package com.egnios.authentication.service.impl;

import com.egnios.authentication.config.auth.firebase.FirebaseTokenHolder;
import com.egnios.authentication.service.IFirebaseService;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.google.firebase.auth.UserRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class FirebaseService implements IFirebaseService {

    private static final Logger logger = LoggerFactory.getLogger(FirebaseService.class);

    @Override
    public Optional<UserRecord> findByEmailName(String email) {
        try {
            return Optional.ofNullable(FirebaseAuth.getInstance().getUserByEmail(email));
        } catch (FirebaseAuthException e) {
            logger.warn("user {} not found in firebase db: {}", email, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public FirebaseTokenHolder parseToken(String firebaseToken) throws FirebaseAuthException {
        try {
            FirebaseToken authTask = FirebaseAuth.getInstance().verifyIdToken(firebaseToken);
            return new FirebaseTokenHolder(authTask);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid token");
        }
    }

    @Override
    public String createUser(String email, String password) throws FirebaseAuthException {
        UserRecord.CreateRequest request = new UserRecord.CreateRequest();
        request.setEmail(email);
        request.setPassword(password);
        request.setDisabled(true);

        UserRecord record = FirebaseAuth.getInstance().createUser(request);
        logger.info("firebase user {} created successfully", record.getUid());

        return record.getUid();
    }

    @Override
    public void deleteUser(String uid) throws FirebaseAuthException {
        FirebaseAuth.getInstance().deleteUser(uid);
        logger.info("firebase user {} deleted successfully", uid);
    }

    @Override
    public void enableUser(String uid) throws FirebaseAuthException {
        UserRecord.UpdateRequest request = new UserRecord.UpdateRequest(uid);
        request.setDisabled(false);
        FirebaseAuth.getInstance().updateUser(request);
        logger.info("firebase user {} enabled", uid);
    }

    @Override
    public void disableUser(String uid) throws FirebaseAuthException {
        UserRecord.UpdateRequest request = new UserRecord.UpdateRequest(uid);
        request.setDisabled(true);
        FirebaseAuth.getInstance().updateUser(request);
        logger.info("firebase user {} disabled", uid);
    }

    @Override
    public void updatePassword(String uid, String password) throws FirebaseAuthException {
        UserRecord.UpdateRequest request = new UserRecord.UpdateRequest(uid);
        request.setPassword(password);
        FirebaseAuth.getInstance().updateUser(request);
        logger.info("firebase user {} password updated", uid);
    }

    @Override
    public void updateDisplayName(String uid, String firstname, String lastname) throws FirebaseAuthException {
        String displayName = String.format("%s %s", firstname, lastname);

        UserRecord.UpdateRequest request = new UserRecord.UpdateRequest(uid);
        request.setDisplayName(displayName);
        FirebaseAuth.getInstance().updateUser(request);
        logger.info("firebase user {} displayname updated", uid);
    }
}
