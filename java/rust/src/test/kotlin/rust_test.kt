import com.github.costinm.dmeshnative.Rust
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.DisplayName

internal class TodoRepositoryTest {

@Test
fun test1() {
    val callback = object : Rust.Callback() {
        override fun callback(s: String) {
            println("Callback received: $s")
        }
    }
    Rust.invokeCallbackViaJNI(callback)
}

}

fun main() {
    val callback = object : Rust.Callback() {
        override fun callback(s: String) {
            println("Callback received: $s")
        }
    }
    Rust.invokeCallbackViaJNI(callback)
}