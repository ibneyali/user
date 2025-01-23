package com.orders.user.repositories;

import com.orders.user.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author Ibney Ali
 */

public interface RoleRepository extends JpaRepository<Role, Integer> {

}
