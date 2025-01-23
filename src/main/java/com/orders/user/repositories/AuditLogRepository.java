package com.orders.user.repositories;

import com.orders.user.entities.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author Ibney Ali
 */

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
}