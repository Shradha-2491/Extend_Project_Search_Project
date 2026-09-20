package com.example.product_search_project.data

import java.util.UUID

class ProductRepository(private val api: ApiService) {

    suspend fun search(term: String): ApiResult<List<Product>> {
        val resp = api.listProducts(term)
        val body = resp.body()
        return if (resp.isSuccessful && body != null) ApiResult.Ok(body.results)
        else ApiResult.Failure(resp.code(), "search_failed")
    }

    suspend fun get(id: Int): ApiResult<Product> {
        val resp = api.getProduct(id)
        val body = resp.body()
        return if (resp.isSuccessful && body != null) ApiResult.Ok(body)
        else ApiResult.Failure(resp.code(), "not_found")
    }

    suspend fun create(name: String, category: String, price: Double, cost: Double, stock: Int): ApiResult<Unit> {
        val resp = api.createProduct(CreateProductRequest(name, category, price, cost, stock))
        return if (resp.isSuccessful) ApiResult.Ok(Unit) else ApiResult.Failure(resp.code(), "create_failed")
    }

    /**
     * Generates a fresh Idempotency-Key per logical user action (i.e. once
     * per tap of "Save price", not per HTTP attempt) so OkHttp's automatic
     * retry-on-network-error and any accidental double-tap can never double-
     * apply the change -- mirrors backend/products.py's products.update_price
     * concurrency-safe implementation, which this call exercises unchanged.
     */
    suspend fun updatePrice(id: Int, newPrice: Double, knownVersion: Int): ApiResult<Product> {
        val idempotencyKey = UUID.randomUUID().toString()
        val resp = api.updatePrice(id, idempotencyKey, PriceUpdateRequest(newPrice, knownVersion))
        val body = resp.body()
        return when {
            resp.isSuccessful && body != null -> ApiResult.Ok(body)
            resp.code() == 409 -> ApiResult.Failure(409, "version_conflict")
            else -> ApiResult.Failure(resp.code(), "price_update_failed")
        }
    }

    suspend fun remove(id: Int): ApiResult<Unit> {
        val resp = api.deleteProduct(id)
        return if (resp.isSuccessful) ApiResult.Ok(Unit) else ApiResult.Failure(resp.code(), "delete_failed")
    }
}

class AdminRepository(private val api: ApiService) {

    suspend fun listUsers(): ApiResult<List<AdminUser>> {
        val resp = api.listUsers()
        val body = resp.body()
        return if (resp.isSuccessful && body != null) ApiResult.Ok(body.results)
        else ApiResult.Failure(resp.code(), "list_failed")
    }

    suspend fun setRole(id: Int, role: String): ApiResult<Unit> {
        val resp = api.updateUser(id, UpdateUserRequest(role = role))
        return if (resp.isSuccessful) ApiResult.Ok(Unit) else ApiResult.Failure(resp.code(), "update_failed")
    }

    suspend fun resetMfa(id: Int): ApiResult<Unit> {
        val resp = api.updateUser(id, UpdateUserRequest(reset_mfa = true))
        return if (resp.isSuccessful) ApiResult.Ok(Unit) else ApiResult.Failure(resp.code(), "update_failed")
    }

    suspend fun deactivate(id: Int): ApiResult<Unit> {
        val resp = api.deactivateUser(id)
        return if (resp.isSuccessful) ApiResult.Ok(Unit) else ApiResult.Failure(resp.code(), "deactivate_failed")
    }
}
