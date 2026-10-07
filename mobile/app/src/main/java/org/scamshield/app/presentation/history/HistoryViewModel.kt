package org.scamshield.app.presentation.history

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import org.scamshield.app.core.database.ScanEntity
import org.scamshield.app.data.repositories.ScanRepository

class HistoryViewModel(private val repository: ScanRepository) : ViewModel() {

    private val _selectedFilter = MutableStateFlow("ALL")
    val selectedFilter: StateFlow<String> = _selectedFilter.asStateFlow()

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val historyItems: StateFlow<List<ScanEntity>> = _selectedFilter
        .flatMapLatest { filter: String ->
            if (filter == "ALL") {
                repository.getLocalHistory()
            } else {
                repository.getHistoryByVerdict(filter)
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    fun setFilter(verdict: String) {
        _selectedFilter.value = verdict
    }

    fun deleteScan(entity: ScanEntity) {
        viewModelScope.launch {
            repository.deleteScan(entity)
        }
    }

    fun clearAll() {
        viewModelScope.launch {
            repository.clearHistory()
        }
    }
}
