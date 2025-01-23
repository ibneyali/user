package com.orders.user.repositories;

import com.orders.user.entities.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author Ibney Ali
 */

@Repository
public interface UserRepository extends CrudRepository<User, Integer> {
	Optional<User> findByEmail(String email);

	Optional<User> findByUsernameOrEmail(String email, String username);

	Optional<User> findByUsername(String username);

}