package org.scamshield.app.presentation.home

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.scamshield.app.core.network.StandardResultDto
import org.scamshield.app.data.repositories.ScanRepository

sealed class HomeUiState {
    object Idle : HomeUiState()
    object Loading : HomeUiState()
    data class Success(val result: StandardResultDto) : HomeUiState()
    data class Error(val message: String) : HomeUiState()
}

class HomeViewModel(private val repository: ScanRepository) : ViewModel() {

    private val _uiState = MutableStateFlow<HomeUiState>(HomeUiState.Idle)
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    var lastResult by mutableStateOf<StandardResultDto?>(null)
        private set

    var isLoading by mutableStateOf(false)
        private set

    fun analyzeText(text: String) {
        if (text.isBlank()) return
        isLoading = true
        _uiState.value = HomeUiState.Loading
        viewModelScope.launch {
            repository.analyzeText(text).fold(
                onSuccess = { res ->
                    isLoading = false
                    lastResult = res
                    _uiState.value = HomeUiState.Success(res)
                },
                onFailure = { err ->
                    isLoading = false
                    _uiState.value = HomeUiState.Error(err.localizedMessage ?: "Analysis failed")
                }
            )
        }
    }

    fun analyzeUrl(url: String) {
        if (url.isBlank()) return
        isLoading = true
        _uiState.value = HomeUiState.Loading
        viewModelScope.launch {
            repository.analyzeUrl(url).fold(
                onSuccess = { res ->
                    isLoading = false
                    lastResult = res
                    _uiState.value = HomeUiState.Success(res)
                },
                onFailure = { err ->
                    isLoading = false
                    _uiState.value = HomeUiState.Error(err.localizedMessage ?: "Analysis failed")
                }
            )
        }
    }

    fun analyzePhone(phone: String, context: String? = null) {
        if (phone.isBlank()) return
        isLoading = true
        _uiState.value = HomeUiState.Loading
        viewModelScope.launch {
            repository.analyzePhone(phone, context).fold(
                onSuccess = { res ->
                    isLoading = false
                    lastResult = res
                    _uiState.value = HomeUiState.Success(res)
                },
                onFailure = { err ->
                    isLoading = false
                    _uiState.value = HomeUiState.Error(err.localizedMessage ?: "Phone check failed")
                }
            )
        }
    }

    fun analyzeQr(content: String) {
        if (content.isBlank()) return
        isLoading = true
        _uiState.value = HomeUiState.Loading
        viewModelScope.launch {
            repository.analyzeQr(content).fold(
                onSuccess = { res ->
                    isLoading = false
                    lastResult = res
                    _uiState.value = HomeUiState.Success(res)
                },
                onFailure = { err ->
                    isLoading = false
                    _uiState.value = HomeUiState.Error(err.localizedMessage ?: "QR analysis failed")
                }
            )
        }
    }

    fun setResult(result: StandardResultDto) {
        isLoading = false
        lastResult = result
        _uiState.value = HomeUiState.Success(result)
    }

    fun resetState() {
        _uiState.value = HomeUiState.Idle
    }
}
