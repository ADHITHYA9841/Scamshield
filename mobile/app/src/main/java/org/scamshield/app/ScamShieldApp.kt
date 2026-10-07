package org.scamshield.app

import android.app.Application
import android.content.Context
import org.scamshield.app.core.database.AppDatabase
import org.scamshield.app.core.locale.AppLocaleManager
import org.scamshield.app.core.network.NetworkClient
import org.scamshield.app.core.service.StorageWatcherService
import org.scamshield.app.data.repositories.ScanRepository

class ScamShieldApp : Application() {

    lateinit var database: AppDatabase
        private set

    lateinit var repository: ScanRepository
        private set

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(AppLocaleManager.applyStoredLocale(base))
    }

    override fun onCreate() {
        super.onCreate()
        NetworkClient.init(this)
        database = AppDatabase.getDatabase(this)
        repository = ScanRepository(
            api = NetworkClient.getApi(),
            scanDao = database.scanDao(),
            appContext = this
        )
        try {
            StorageWatcherService.startService(this)
        } catch (e: Throwable) {}
    }
}
