import com.github.costinm.dmeshnative.MeshNode
import com.github.costinm.dmeshnative.Rust
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

internal class RustBridgeApiTest {

    @Test
    fun exposesCurrentMeshApi() {
        Assertions.assertNotNull(Rust::class.java.getDeclaredMethod("load"))
        Assertions.assertNotNull(MeshNode::class.java.getDeclaredMethod("start", Int::class.java, Int::class.java))
        Assertions.assertNotNull(MeshNode::class.java.getDeclaredMethod("getPublicKey"))
        Assertions.assertNotNull(MeshNode::class.java.getDeclaredMethod("stop"))
    }
}
