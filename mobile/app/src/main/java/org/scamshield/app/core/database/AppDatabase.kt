package org.scamshield.app.core.database

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppDatabase private constructor(context: Context) {

    private val dbHelper = DatabaseHelper(context.applicationContext)
    private val dao = SQLiteScanDao(dbHelper)

    fun scanDao(): ScanDao = dao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = AppDatabase(context)
                INSTANCE = instance
                instance
            }
        }
    }

    private class DatabaseHelper(context: Context) :
        SQLiteOpenHelper(context, "scamshield_local.db", null, 1) {

        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    scanId TEXT PRIMARY KEY NOT NULL,
                    timestamp INTEGER NOT NULL,
                    inputType TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    riskScore INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    scamType TEXT NOT NULL,
                    language TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    evidenceJson TEXT NOT NULL,
                    recommendedActionsJson TEXT NOT NULL
                );
                """.trimIndent()
            )
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            db.execSQL("DROP TABLE IF EXISTS scan_history")
            onCreate(db)
        }
    }

    private class SQLiteScanDao(private val dbHelper: DatabaseHelper) : ScanDao {

        private val daoScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        private val _scansState = MutableStateFlow<List<ScanEntity>>(emptyList())

        init {
            refreshCache()
        }

        private fun refreshCache() {
            daoScope.launch {
                val list = queryAllInternal()
                _scansState.value = list
            }
        }

        private fun queryAllInternal(): List<ScanEntity> {
            val list = mutableListOf<ScanEntity>()
            val db = dbHelper.readableDatabase
            val cursor = db.rawQuery("SELECT * FROM scan_history ORDER BY timestamp DESC", null)
            cursor.use { c ->
                while (c.moveToNext()) {
                    list.add(cursorToEntity(c))
                }
            }
            return list
        }

        private fun cursorToEntity(c: Cursor): ScanEntity {
            return ScanEntity(
                scanId = c.getString(c.getColumnIndexOrThrow("scanId")),
                timestamp = c.getLong(c.getColumnIndexOrThrow("timestamp")),
                inputType = c.getString(c.getColumnIndexOrThrow("inputType")),
                verdict = c.getString(c.getColumnIndexOrThrow("verdict")),
                riskScore = c.getInt(c.getColumnIndexOrThrow("riskScore")),
                confidence = c.getFloat(c.getColumnIndexOrThrow("confidence")),
                scamType = c.getString(c.getColumnIndexOrThrow("scamType")),
                language = c.getString(c.getColumnIndexOrThrow("language")),
                explanation = c.getString(c.getColumnIndexOrThrow("explanation")),
                evidenceJson = c.getString(c.getColumnIndexOrThrow("evidenceJson")),
                recommendedActionsJson = c.getString(c.getColumnIndexOrThrow("recommendedActionsJson"))
            )
        }

        override suspend fun insertScan(scan: ScanEntity) = withContext(Dispatchers.IO) {
            val db = dbHelper.writableDatabase
            val cv = ContentValues().apply {
                put("scanId", scan.scanId)
                put("timestamp", scan.timestamp)
                put("inputType", scan.inputType)
                put("verdict", scan.verdict)
                put("riskScore", scan.riskScore)
                put("confidence", scan.confidence)
                put("scamType", scan.scamType)
                put("language", scan.language)
                put("explanation", scan.explanation)
                put("evidenceJson", scan.evidenceJson)
                put("recommendedActionsJson", scan.recommendedActionsJson)
            }
            db.insertWithOnConflict(
                "scan_history",
                null,
                cv,
                SQLiteDatabase.CONFLICT_REPLACE
            )
            refreshCache()
        }

        override fun getAllScans(): Flow<List<ScanEntity>> = _scansState

        override fun getScansByVerdict(verdict: String): Flow<List<ScanEntity>> {
            return _scansState.map { list ->
                list.filter { it.verdict.equals(verdict, ignoreCase = true) }
            }
        }

        override fun searchScans(query: String): Flow<List<ScanEntity>> {
            return _scansState.map { list ->
                if (query.isBlank()) list
                else list.filter {
                    it.scamType.contains(query, ignoreCase = true) ||
                            it.explanation.contains(query, ignoreCase = true) ||
                            it.inputType.contains(query, ignoreCase = true)
                }
            }
        }

        override suspend fun getScanById(id: String): ScanEntity? = withContext(Dispatchers.IO) {
            val db = dbHelper.readableDatabase
            val cursor = db.rawQuery("SELECT * FROM scan_history WHERE scanId = ? LIMIT 1", arrayOf(id))
            cursor.use { c ->
                if (c.moveToFirst()) cursorToEntity(c) else null
            }
        }

        override suspend fun deleteScan(scan: ScanEntity) = withContext(Dispatchers.IO) {
            val db = dbHelper.writableDatabase
            db.delete("scan_history", "scanId = ?", arrayOf(scan.scanId))
            refreshCache()
        }

        override suspend fun clearAllScans() = withContext(Dispatchers.IO) {
            val db = dbHelper.writableDatabase
            db.delete("scan_history", null, null)
            refreshCache()
        }

        override suspend fun getTotalCount(): Int = withContext(Dispatchers.IO) {
            val db = dbHelper.readableDatabase
            val cursor = db.rawQuery("SELECT COUNT(*) FROM scan_history", null)
            cursor.use { c ->
                if (c.moveToFirst()) c.getInt(0) else 0
            }
        }

        override suspend fun getScamCount(): Int = withContext(Dispatchers.IO) {
            val db = dbHelper.readableDatabase
            val cursor = db.rawQuery("SELECT COUNT(*) FROM scan_history WHERE verdict = 'SCAM'", null)
            cursor.use { c ->
                if (c.moveToFirst()) c.getInt(0) else 0
            }
        }

        override suspend fun getSuspiciousCount(): Int = withContext(Dispatchers.IO) {
            val db = dbHelper.readableDatabase
            val cursor = db.rawQuery("SELECT COUNT(*) FROM scan_history WHERE verdict = 'SUSPICIOUS'", null)
            cursor.use { c ->
                if (c.moveToFirst()) c.getInt(0) else 0
            }
        }

        override suspend fun getSafeCount(): Int = withContext(Dispatchers.IO) {
            val db = dbHelper.readableDatabase
            val cursor = db.rawQuery("SELECT COUNT(*) FROM scan_history WHERE verdict = 'SAFE'", null)
            cursor.use { c ->
                if (c.moveToFirst()) c.getInt(0) else 0
            }
        }

        override suspend fun getCategoryBreakdown(): Map<String, Int> = withContext(Dispatchers.IO) {
            val db = dbHelper.readableDatabase
            val cursor = db.rawQuery("SELECT scamType, COUNT(*) FROM scan_history WHERE scamType IS NOT NULL AND scamType != '' GROUP BY scamType ORDER BY COUNT(*) DESC LIMIT 6", null)
            val map = mutableMapOf<String, Int>()
            cursor.use { c ->
                while (c.moveToNext()) {
                    val cat = c.getString(0) ?: "General Fraud"
                    val count = c.getInt(1)
                    map[cat] = count
                }
            }
            map
        }
    }
}
