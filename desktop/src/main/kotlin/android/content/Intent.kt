package android.content

/** A command for the tunnel service: the component class and an action. */
class Intent(@Suppress("unused") val context: Context, @Suppress("unused") val component: Class<*>) {
    private var actionName: String? = null

    val action: String? get() = actionName

    fun setAction(a: String?): Intent {
        actionName = a
        return this
    }
}
