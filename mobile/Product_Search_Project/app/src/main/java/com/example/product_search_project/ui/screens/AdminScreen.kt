package com.example.product_search_project.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.product_search_project.ui.AppViewModel
import com.example.product_search_project.ui.Screen

@Composable
fun AdminUsersScreen(vm: AppViewModel) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        TextButton(onClick = { vm.goTo(Screen.Products) }) { Text("<- Back") }
        Text("User administration")
        LazyColumn {
            items(vm.users) { u ->
                Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                    Text("${u.username} (${u.role}, ${u.auth_provider}) -- active=${u.active}, mfa=${u.mfa_enabled}")
                    Row {
                        if (u.role != "vendor") {
                            TextButton(onClick = { vm.setRole(u.id, "vendor") }) { Text("Make vendor") }
                        }
                        if (u.role != "admin") {
                            TextButton(onClick = { vm.setRole(u.id, "admin") }) { Text("Make admin") }
                        }
                        TextButton(onClick = { vm.deactivateUser(u.id) }) { Text("Deactivate") }
                    }
                }
            }
        }
    }
}
