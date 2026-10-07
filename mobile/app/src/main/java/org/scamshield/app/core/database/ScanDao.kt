package org.scamshield.app.core.database

import kotlinx.coroutines.flow.Flow

interface ScanDao {
    suspend fun insertScan(scan: ScanEntity)
    fun getAllScans(): Flow<List<ScanEntity>>
    fun getScansByVerdict(verdict: String): Flow<List<ScanEntity>>
    fun searchScans(query: String): Flow<List<ScanEntity>>
    suspend fun getScanById(id: String): ScanEntity?
    suspend fun deleteScan(scan: ScanEntity)
    suspend fun clearAllScans()
    suspend fun getTotalCount(): Int
    suspend fun getScamCount(): Int
    suspend fun getSuspiciousCount(): Int
    suspend fun getSafeCount(): Int
    suspend fun getCategoryBreakdown(): Map<String, Int>
}
