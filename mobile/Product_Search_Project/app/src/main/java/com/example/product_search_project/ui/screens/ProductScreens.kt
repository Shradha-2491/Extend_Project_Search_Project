package com.example.product_search_project.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.product_search_project.data.Product
import com.example.product_search_project.ui.AppViewModel
import com.example.product_search_project.ui.Screen

@Composable
fun ProductListScreen(vm: AppViewModel) {
    var term by remember { mutableStateOf("") }
    val role = vm.role

    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        Row {
            Text("Signed in as ${vm.username} ($role)", modifier = Modifier.fillMaxWidth())
        }
        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            OutlinedTextField(term, { term = it }, label = { Text("Search") }, modifier = Modifier.fillMaxWidth(0.7f))
            Button(onClick = { vm.loadProducts(term) }) { Text("Go") }
        }
        Row {
            if (role == "admin") TextButton(onClick = { vm.goTo(Screen.AdminUsers) }) { Text("User admin") }
            TextButton(onClick = { vm.logout() }) { Text("Log out") }
        }
        HorizontalDivider()
        LazyColumn {
            items(vm.products) { p: Product ->
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column {
                        Text("${p.name} (${p.category})")
                        Text("$${"%.2f".format(p.price)}" + (p.stock?.let { " -- stock $it" } ?: ""))
                    }
                    if (role == "vendor" || role == "admin") {
                        TextButton(onClick = { vm.goTo(Screen.ProductDetail(p.id)) }) { Text("Manage") }
                    }
                }
            }
        }
    }
}

@Composable
fun ProductDetailScreen(vm: AppViewModel, productId: Int) {
    val product = vm.selectedProduct
    var newPrice by remember { mutableStateOf("") }

    Column(
        Modifier.fillMaxWidth().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = { vm.goTo(Screen.Products) }) { Text("<- Back") }
        if (product == null) {
            Text("Loading...")
        } else {
            Text("${product.name} (#${product.id})")
            Text("Current price: $${"%.2f".format(product.price)} -- version ${product.version}")
            Text(
                "Updating sends the version you last saw, so a retry or double-tap can't " +
                    "double-apply the change, and a concurrent edit elsewhere is rejected instead " +
                    "of silently overwritten.",
            )
            OutlinedTextField(newPrice, { newPrice = it }, label = { Text("New price") }, modifier = Modifier.fillMaxWidth())
            vm.errorMessage?.let { Text("Error: $it") }
            Button(
                onClick = {
                    val price = newPrice.toDoubleOrNull()
                    val version = product.version
                    if (price != null && version != null) {
                        vm.updatePrice(productId, price, version) { newPrice = "" }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Update price") }
        }
    }
}
